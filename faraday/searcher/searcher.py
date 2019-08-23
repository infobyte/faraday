#!/usr/bin/env python
# -*- coding: utf-8 -*-

###
## Faraday Penetration Test IDE
## Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

import os
import re
import sys
import ast
import json
import signal
import smtplib
import logging
import time

import requests
import subprocess
from datetime import datetime

import click
from difflib import SequenceMatcher
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from faraday.server.web import app
from faraday.server.models import db, Service, Host, VulnerabilityWeb, Vulnerability
from faraday.searcher.sqlapi import SqlApi
from faraday.searcher.validator import validate_rules
from faraday.searcher.api import Api

logger = logging.getLogger('Faraday searcher')

threshold = 0.75
min_weight = 0.3


class MailNotification:
    def __init__(self, mail_from, mail_password, mail_protocol, mail_port):
        self.mail_from = mail_from
        self.mail_password = mail_password
        self.mail_protocol = mail_protocol
        self.mail_port = mail_port

    def send_mail(self, to_addr, subject, body):
        from_addr = self.mail_from
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))
        try:
            server_mail = smtplib.SMTP(self.mail_protocol, self.mail_port)
            server_mail.starttls()
            server_mail.login(from_addr, self.mail_password)
            text = msg.as_string()
            server_mail.sendmail(from_addr, to_addr, text)
            server_mail.quit()
        except Exception as error:
            logger.error("Error: unable to send email")
            logger.exception(error)


def compare(a, b):
    return SequenceMatcher(None, a, b).ratio()


def get_cwe(api, data):
    logger.debug("Getting vulnerability templates")
    templates = api.get_filtered_templates(id=data, name=data)
    if len(templates) > 0:
        return templates.pop()
    return None


def is_same_level(model1, model2):
    return model1.parent_id == model2.parent_id and model1.parent_type == model2.parent_type


def equals(m1, m2, rule):
    logger.debug("Comparing by similarity '%s' and '%s'" % (m1.name, m2.name))
    match = True
    total_ratio = 0
    count_fields = 0

    for field in rule['fields']:
        f_m1 = getattr(m1, field, None)
        f_m2 = getattr(m2, field, None)

        if f_m1 is not None and f_m2 is not None:
            if field == 'severity' or field == 'owner' or field == 'status':
                if f_m1 == f_m2:
                    ratio = 1.0
                else:
                    ratio = min_weight

            elif isinstance(f_m1, str) or isinstance(f_m1, unicode) and isinstance(f_m2, str) or isinstance(f_m2,
                                                                                                            unicode):
                ratio = compare(f_m1.lower().replace('\n', ' '), f_m2.lower().replace('\n', ' '))

            elif isinstance(f_m1, bool) and isinstance(f_m2, bool):
                if f_m1 == f_m2:
                    ratio = 1.0
                else:
                    ratio = 0.0
            else:
                ratio = -1

        if ratio is not -1:
            total_ratio += ratio
            count_fields += 1

    if total_ratio != 0:
        percent = (total_ratio * 100) / count_fields
    else:
        percent = 0.0
    logger.debug("Verify result with %.2f %% evaluating rule %s:" % (percent, rule['id']))

    if match and total_ratio >= (threshold * count_fields):
        logger.info("MATCH")
        return True
    return False


def get_model_environment(model, _models):
    environment = []
    for md in _models:
        if is_same_level(model, md):
            environment.append(md)
    return environment


def process_models_by_similarity(api, _models, rule, mail_notificacion):
    logger.debug("--> Start Process models by similarity")
    for index_m1, m1 in zip(range(len(_models) - 1), _models):
        for index_m2, m2 in zip(range(index_m1 + 1, len(_models)), _models[index_m1 + 1:]):
            if m1.id != m2.id and is_same_level(m1, m2):
                if equals(m1, m2, rule):
                    environment = [m1, m2]
                    _objs_value = None
                    if 'object' in rule:
                        _objs_value = rule['object']
                    _object = get_object(environment, _objs_value)
                    if _object is not None:
                        if 'conditions' in rule:
                            environment = get_model_environment(m2, _models)
                            if can_execute_action(environment, rule['conditions']):
                                execute_action(api, _object, rule, mail_notificacion)
                        else:
                            execute_action(api, _object, rule, mail_notificacion)
    logger.debug("<-- Finish Process models by similarity")


def get_field(obj, field):
    try:
        if field in obj.__dict__:
            return getattr(obj, field)
        return None
    except AttributeError:
        logger.error("ERROR: Field %s is invalid" % field)
        return None


def set_array(field, value, add=True):
    if isinstance(field, list):
        if add:
            if value not in field:
                field.append(value)
        else:
            if value in field:
                field.remove(value)


def update_service(api, service, key, value):
    if key == 'owned':
        value = value == 'True'
        service.owned = value
        logger.info("Changing property %s to %s in service '%s' with id %s" % (key, value, service.name, service.id))
    else:
        to_add = True
        if key.startswith('-'):
            key = key.strip('-')
            to_add = False

        field = get_field(service, key)
        if field is not None:
            if isinstance(field, (str, unicode)):
                setattr(service, key, value)
                logger.info(
                    "Changing property %s to %s in service '%s' with id %s" % (key, value, service.name, service.id))
            else:
                set_array(field, value, add=to_add)
                action = 'Adding %s to %s list in service %s with id %s' % (value, key, service.name, service.id)
                if not to_add:
                    action = 'Removing %s from %s list in service %s with id %s' % (
                        value, key, service.name, service.id)

                logger.info(action)

    api.update_service(service)

    logger.info("Done")
    return True


def update_host(api, host, key, value):
    if key == 'owned':
        value = value == 'True'
        host.owned = value
        logger.info("Changing property %s to %s in host '%s' with id %s" % (key, value, host.name, host.id))
    else:
        to_add = True
        if key.startswith('-'):
            key = key.strip('-')
            to_add = False

        field = get_field(host, key)
        if field is not None:
            if isinstance(field, (str, unicode)):
                setattr(host, key, value)
                logger.info("Changing property %s to %s in host '%s' with id %s" % (key, value, host.name, host.id))
            else:
                set_array(field, value, add=to_add)
                action = 'Adding %s to %s list in host %s with id %s' % (value, key, host.name, host.id)
                if not to_add:
                    action = 'Removing %s from %s list in host %s with id %s' % (
                        value, key, host.name, host.id)

                logger.info(action)
    api.update_host(host)

    logger.info("Done")
    return True


def evaluate_condition(model, condition):
    key, value = condition.split('=')
    value = value.replace('%', ' ')
    if key == 'regex':
        if re.match(value, model.name) is None:
            return False
        return True

    temp_value = getattr(model, key, None)
    if key in model.getMetadata():
        temp_value = model.getMetadata()[key]

    if temp_value is None:
        return False

    if isinstance(temp_value, list):
        if value not in temp_value and str(value) not in temp_value:
            if not isinstance(value, int):
                return False
            elif int(value) not in temp_value:
                return False
        return True

    if isinstance(temp_value, bool):
        if value == 'True' and not temp_value:
            return False
        if value == 'False' and temp_value:
            return False
        return True

    if isinstance(temp_value, int):
        return value == str(temp_value)

    if value.encode("utf-8") != temp_value.encode("utf-8"):
        return False
    return True


def evaluate_conditions(_models, conditions):
    logger.debug("Evaluating conditions")
    for model in _models:
        if all([evaluate_condition(model, cond) for cond in conditions]):
            return True
    return False


def can_execute_action(_models, conditions):
    for conds in conditions:
        conds = conds.split()
        if not evaluate_conditions(_models, conds):
            return False
    return True


def execute_action(api, objects, rule, mail_notificacion=None):
    logger.info("Running actions of rule '%s' :" % rule['id'])
    actions = rule['actions']
    _objs_value = None
    if 'object' in rule:
        _objs_value = rule['object']

    for obj in objects:
        for action in actions:
            action = action.strip('--')
            array = action.split(':')
            command = array[0]
            expression = str(':').join(array[1:])

            if command == 'UPDATE':
                array_exp = expression.split('=')
                key = array_exp[0]
                value = str('=').join(array_exp[1:])
                if obj.class_signature == 'VulnerabilityWeb' or obj.class_signature == 'Vulnerability':
                    update_vulnerability(api, obj, key, value)

                if obj.class_signature == 'Service':
                    update_service(api, obj, key, value)

                if obj.class_signature == 'Host':
                    update_host(api, obj, key, value)

            elif command == 'DELETE':
                if obj.class_signature == 'VulnerabilityWeb' or obj.class_signature == 'Vulnerability':
                    api.delete_vulnerability(obj.id)
                    logger.info("Deleting vulnerability '%s' with id '%s':" % (obj.name, obj.id))

                elif obj.class_signature == 'Service':
                    api.delete_service(obj.id)
                    logger.info("Deleting service '%s' with id '%s':" % (obj.name, obj.id))

                elif obj.class_signature == 'Host':
                    api.delete_host(obj.id)
                    logger.info("Deleting host '%s' with id '%s':" % (obj.name, obj.id))
            else:
                subject = 'Faraday searcher alert'
                body = '%s %s have been modified by rule %s at %s' % (
                    obj.class_signature, obj.name, rule['id'], str(datetime.now()))
                mail_notificacion.send_mail(expression, subject, body)
                logger.info("Sending mail to: '%s'" % expression)
    return True


def replace_rule(rule, value_item):
    if value_item is None:
        return rule

    rule_str = json.dumps(rule)
    r = re.findall("\{\{(.*?)\}\}", rule_str)
    _vars = list(set(r))
    for var in _vars:
        value = value_item[var]
        rule_str = rule_str.replace('{{' + var + '}}', value)

    return ast.literal_eval(rule_str)


def parse_value(value):
    if value == 'info':
        return 'informational'
    if value == 'med':
        return 'medium'


# TODO: REMOVE
def get_objects_by_parent(parent, objects_type):
    if isinstance(parent, Service) and objects_type == 'Vulnerability':
        return parent.vulnerabilities + parent.web_vulnerabilities
    elif isinstance(parent, Host) and objects_type == 'Vulnerability':
        return parent.vulnerabilities
    elif isinstance(parent, Host) and objects_type == 'Service':
        return parent.services
    else:
        return None


def process_services(api, services, mail_notificacion, rules):
    logger.debug("--> Start Process services")
    for rule in rules:
        if rule['model'] == 'Service':
            services = get_models(api, services, rule)
            if 'fields' in rule:
                process_models_by_similarity(api, services, rule, mail_notificacion)
            else:
                _objs_value = None
                if 'object' in rule:
                    _objs_value = rule['object']
                objects = get_object(services, _objs_value)
                if objects is not None and len(objects) != 0:
                    if 'conditions' in rule:
                        if can_execute_action(services, rule['conditions']):
                            execute_action(api, objects, rule, mail_notificacion)
                    else:
                        execute_action(api, objects, rule, mail_notificacion)
    logger.debug("<-- Finish Process services")


def process_hosts(api, hosts, mail_notificacion, rules):
    logger.debug("--> Start Process Hosts")
    for rule in rules:
        if rule['model'] == 'Host':
            hosts = get_models(api, hosts, rule)
            if 'fields' in rule:
                process_models_by_similarity(api, hosts, rule, mail_notificacion)
            else:
                _objs_value = None
                if 'object' in rule:
                    _objs_value = rule['object']
                objects = get_object(hosts, _objs_value)
                if objects is not None and len(objects) != 0:
                    if 'conditions' in rule:
                        if can_execute_action(hosts, rule['conditions']):
                            execute_action(api, objects, rule, mail_notificacion)
                    else:
                        execute_action(api, objects, rule, mail_notificacion)
        logger.debug("<-- Finish Process Hosts")


def signal_handler(signal, frame):
    os.remove(".lock.pod")
    logger.info('Killed')
    sys.exit(0)


class Searcher:
    def __init__(self, api, mail_notificacion=None, tool_name='Searcher'):
        self.tool_name = tool_name
        self.api = api
        self.mail_notificacion = mail_notificacion

        # logger.debug("Getting hosts ...")
        # self.hosts = self.api.get_hosts()
        #
        # logger.debug("Getting services ...")
        # self.services = self.api.get_services()

        # logger.debug("Getting vulnerabilities ...")
        # self.vulns = self.api.get_vulnerabilities()

    def process(self, rules):
        if rules and validate_rules(rules):
            start = datetime.now()
            command_id = self.api.create_command(
                itime=time.mktime(start.timetuple()),
                params=rules,
                tool_name=self.tool_name
            )
            self.api.command_id = command_id
            self._process_vulnerabilities(rules)

            # process_services(
            #     self.api,
            #     self.services,
            #     self.mail_notificacion,
            #     rules
            # )
            # process_hosts(
            #     self.api,
            #     self.hosts,
            #     self.mail_notificacion,
            #     rules
            # )
            duration = (datetime.now() - start).seconds
            self.api.close_command(command_id, duration)

    def _process_vulnerabilities(self, rules):
        logger.debug("--> Start Process vulnerabilities")
        for rule_item in rules:
            logger.debug('Processing rule {}'.format(rule_item['id']))
            if rule_item['model'] == 'Vulnerability':
                count_values = 1
                values = [None]
                if 'values' in rule_item and len(rule_item['values']) > 0:
                    values = rule_item['values']
                    count_values = len(values)

                for index in range(count_values):
                    rule = replace_rule(rule_item, values[index])
                    vulnerabilities, parent = self._get_models(rule)
                    if 'fields' in rule:
                        process_models_by_similarity(self.api, vulnerabilities, rule, self.mail_notificacion)
                    else:
                        objects = self._get_object(rule)
                        objects = self.api.intersection(objects, vulnerabilities)
                        if objects is not None and len(objects) != 0:
                            if self._can_execute_action(rule, parent):
                                self._execute_action(objects, rule)

        logger.debug("<-- Finish Process vulnerabilities")

    def _fetch_objects(self, rule_model):
        if rule_model == 'Vulnerability':
            return self.api.fetch_vulnerabilities()
        if rule_model == 'Service':
            return self.api.fetch_services()
        if rule_model == 'Host':
            return self.api.fetch_hosts()

    def _filter_objects(self, rule_model, **kwargs):
        if rule_model == 'Vulnerability':
            return self.api.filter_vulnerabilities(**kwargs)
        if rule_model == 'Service':
            return self.api.filter_services(**kwargs)
        if rule_model == 'Host':
            return self.api.filter_hosts(**kwargs)

    def _get_models(self, rule):
        logger.debug("Getting models")
        if 'parent' in rule:
            parent = self._get_parent(rule['parent'])
            if parent is None:
                logger.warning("WARNING: Parent %s not found in rule %s " % (rule['parent'], rule['id']))
                return self._fetch_objects(rule['model']), None
            return self._get_objects_by_parent(parent, rule['model']), parent
        return self._fetch_objects(rule['model']), None

    def _get_parent(self, parent_tag):
        logger.debug("Getting parent")
        parents = self.api.filter_services(id=parent_tag) or \
                  self.api.filter_services(name=parent_tag) or \
                  self.api.filter_hosts(id=parent_tag) or \
                  self.api.filter_hosts(ip=parent_tag)
        if len(parents) > 0:
            return parents[0]
        return None

    def _get_object(self, rule):
        logger.debug("Getting object")
        if 'object' in rule:
            rule_obj = rule['object']
        else:
            return None

        items = rule_obj.split()
        allow_old_option = '--old' in items
        if allow_old_option:
            items.remove('--old')
        kwargs = {}
        for item in items:
            key, value = item.split('=')
            kwargs[key] = value

        objects = self._filter_objects(rule['model'], **kwargs)
        if len(objects) == 0:
            objects = self._fetch_objects(rule['model'])
        return objects

    def _get_objects_by_parent(self, parent, objects_type):
        if isinstance(parent, Service) and objects_type == 'Vulnerability':
            return parent.vulnerabilities + parent.web_vulnerabilities
        elif isinstance(parent, Host) and objects_type == 'Vulnerability':
            return parent.vulnerabilities
        elif isinstance(parent, Host) and objects_type == 'Service':
            return parent.services
        else:
            if parent.type == 'Service' and objects_type == 'Vulnerability':
                return self.api.filter_vulnerabilities(service_id=parent.id)
            elif parent.type == 'Host' and objects_type == 'Vulnerability':
                return self.api.filter_vulnerabilities(host_id=parent.id)
            elif parent.type == 'Host' and objects_type == 'Service':
                return self.api.filter_services(host_id=parent.id)
            else:
                return None

    def _can_execute_action(self, rule, parent):
        if 'conditions' not in rule:
            return True

        kwargs = {}
        if parent is not None:
            if isinstance(parent, Service):
                kwargs['service_id'] = parent.id
            elif isinstance(parent, Host):
                kwargs['host_id'] = parent.id

        conditions = rule['conditions']
        for condition in conditions:
            key, value = condition.split('=')
            kwargs[key] = value

        return len(self._filter_objects(rule['model'], **kwargs)) > 0

    def _execute_action(self, objects, rule):
        logger.info("Running actions of rule '%s' :" % rule['id'])
        actions = rule['actions']
        _objs_value = None
        if 'object' in rule:
            _objs_value = rule['object']

        for obj in objects:
            for action in actions:
                action = action.strip('--')
                array = action.split(':')
                command = array[0]
                expression = str(':').join(array[1:])

                if command == 'UPDATE':
                    array_exp = expression.split('=')
                    key = array_exp[0]
                    value = str('=').join(array_exp[1:])
                    if obj.type.capitalize() == 'VulnerabilityWeb' or obj.type.capitalize() == 'Vulnerability':
                        self._update_vulnerability(obj, key, value)

                    if obj.type.capitalize() == 'Service':
                        update_service(self.api, obj, key, value)

                    if obj.type.capitalize() == 'Host':
                        update_host(self.api, obj, key, value)

                elif command == 'DELETE':
                    if obj.type.capitalize() == 'VulnerabilityWeb' or obj.type.capitalize() == 'Vulnerability':
                        self.api.delete_vulnerability(obj.id)
                        logger.info("Deleting vulnerability '%s' with id '%s':" % (obj.name, obj.id))

                    elif obj.type.capitalize() == 'Service':
                        self.api.delete_service(obj.id)
                        logger.info("Deleting service '%s' with id '%s':" % (obj.name, obj.id))

                    elif obj.type.capitalize() == 'Host':
                        self.api.delete_host(obj.id)
                        logger.info("Deleting host '%s' with id '%s':" % (obj.name, obj.id))
                else:
                    subject = 'Faraday searcher alert'
                    body = '%s %s have been modified by rule %s at %s' % (
                        obj.class_signature, obj.name, rule['id'], str(datetime.now()))
                    self.mail_notificacion.send_mail(expression, subject, body)
                    logger.info("Sending mail to: '%s'" % expression)
        return True

    def _update_vulnerability(self, vuln, key, value):
        value = parse_value(value)
        if key == 'template':
            cwe = get_cwe(self.api, value)
            if cwe is None:
                logger.error("%s: cwe not found" % value)
                return False

            vuln.name = cwe.name
            vuln.description = cwe.description
            vuln.desc = cwe.description
            vuln.resolution = cwe.resolution

            logger.info("Applying template '%s' to vulnerability '%s' with id '%s'" % (value, vuln.name, vuln.id))

        elif key == 'confirmed':
            value = value == 'True'
            vuln.confirmed = value
            logger.info(
                "Changing property %s to %s in vulnerability '%s' with id %s" % (key, value, vuln.name, vuln.id))
        elif key == 'owned':
            value = value == 'True'
            vuln.owned = value
            logger.info(
                "Changing property %s to %s in vulnerability '%s' with id %s" % (key, value, vuln.name, vuln.id))
        else:
            to_add = True
            if key.startswith('-'):
                key = key.strip('-')
                to_add = False

            is_custom_field = False
            if vuln.custom_fields is not None and key in vuln.custom_fields:
                field = vuln.custom_fields
                is_custom_field = True
            else:
                field = get_field(vuln, key)

            if field is not None and is_custom_field is False:
                if isinstance(field, (str, unicode)):
                    setattr(vuln, key, value)
                    logger.info(
                        "Changing property %s to %s in vulnerability '%s' with id %s" % (
                        key, value, vuln.name, vuln.id))
                else:
                    set_array(field, value, add=to_add)
                    action = 'Adding %s to %s list in vulnerability %s with id %s' % (value, key, vuln.name, vuln.id)
                    if not to_add:
                        action = 'Removing %s from %s list in vulnerability %s with id %s' % (
                            value, key, vuln.name, vuln.id)

                    logger.info(action)

            if field is not None and is_custom_field is True:
                vuln.custom_fields[key] = value
                logger.info(
                    "Changing custom field %s to %s in vulnerability '%s' with id %s" % (
                    key, value, vuln.name, vuln.id))

        result = self.api.update_vulnerability(vuln)
        if result is False:
            return result
        logger.info("Done")
        return True


@click.command()
@click.option('--workspace', required=True, prompt=True, help='Workspacer name')
@click.option('--server_address', required=True, prompt=True, help='Faraday server address')
@click.option('--user', required=True, prompt=True, help='')
@click.option('--password', required=True, prompt=True, hide_input=True, help='')
@click.option('--output', required=False, help='Choose a custom output directory', default='output')
@click.option('--email', required=False)
@click.option('--email_password', required=False)
@click.option('--mail_protocol', required=False)
@click.option('--port_protocol', required=False, default=587)
@click.option('--log', required=False, default='debug')
@click.option('--rules', required=True, prompt=True, help='Filename with rules')
def main(workspace, server_address, user, password, output, email, email_password, mail_protocol, port_protocol, log,
         rules):
    signal.signal(signal.SIGINT, signal_handler)

    loglevel = log
    with open(rules, 'r') as rules_file:
        try:
            rules = json.loads(rules_file.read())
        except Exception:
            print("Invalid rules file.")
            sys.exit(1)

    mail_notificacion = MailNotification(
        email,
        email_password,
        mail_protocol,
        port_protocol,

    )

    for d in [output, 'log/']:
        if not os.path.isdir(d):
            os.makedirs(d)

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    if not logger.handlers:
        logger.propagate = 0
        logger.setLevel(numeric_level)
        fh = logging.FileHandler('log/searcher.log')
        fh.setLevel(numeric_level)
        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(numeric_level)
        # create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s[%(pathname)s %(lineno)d ]: %(message)s',
                                      datefmt='%m/%d/%Y %I:%M:%S %p')

        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

    try:
        logger.info('Started')
        logger.info('Searching objects into workspace %s ' % workspace)

        if not server_address.endswith('/'):
            server_address += '/'
        if not server_address.endswith('/_api'):
            server_address += '_api'

        api = Api(requests, workspace, user, password, base=server_address)
        searcher = Searcher(api, mail_notificacion)
        searcher.process(rules)

        logger.info('Finished')
    except Exception as error:
        logger.exception(error)


if __name__ == "__main__":
    main()
