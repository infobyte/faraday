#!/usr/bin/env python
# -*- coding: utf-8 -*-

###
# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
###
from builtins import str

import ast
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path

import click
import requests

from faraday.searcher.api import Api
from faraday.searcher.validator import validate_rules
from faraday.server.models import Service, Host
from faraday.utils.smtp import MailNotification

logger = logging.getLogger('Faraday searcher')

threshold = 0.75
min_weight = 0.3


def compare(a, b):
    return SequenceMatcher(None, a, b).ratio()


def get_cwe(api, data):
    logger.debug("Getting vulnerability templates")
    templates_filtered_by_id = api.filter_templates(id=data)
    templates_filtered_by_name = api.filter_templates(name=data)
    templates = templates_filtered_by_id + templates_filtered_by_name
    if len(templates) > 0:
        return templates.pop()
    return None


def is_same_level(model1, model2):
    try:
        return model1.parent_id == model2.parent_id and model1.parent_type == model2.parent_type
    except AttributeError:
        if not isinstance(model1, type(model2)):
            return False
        parent_type = type(model1.parent).__name__
        if parent_type == 'Service':
            return model1.service_id == model2.service_id
        elif parent_type == 'Host':
            return model1.host_id == model2.host_id
        return False


def equals(m1, m2, rule):
    logger.debug(f"Comparing by similarity '{m1.name}' and '{m2.name}'")
    match = True
    total_ratio = 0
    count_fields = 0

    for field in rule['fields']:
        f_m1 = getattr(m1, field, None)
        f_m2 = getattr(m2, field, None)

        if f_m1 is not None and f_m2 is not None:
            if field in ['severity', 'owner', 'status']:
                if f_m1 == f_m2:
                    ratio = 1.0
                else:
                    ratio = min_weight

            elif isinstance(f_m1, str) or isinstance(f_m2, str):
                ratio = compare(f_m1.lower().replace('\n', ' '), f_m2.lower().replace('\n', ' '))

            elif isinstance(f_m1, bool) and isinstance(f_m2, bool):
                if f_m1 == f_m2:
                    ratio = 1.0
                else:
                    ratio = 0.0
            else:
                ratio = -1

        if ratio != -1:
            total_ratio += ratio
            count_fields += 1

    if total_ratio != 0:
        percent = (total_ratio * 100.0) / count_fields
    else:
        percent = 0.0
    logger.debug(f"Verify result with {percent:.2f} % evaluating rule {rule['id']}:")

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


def get_field(obj, field):
    try:
        if field in obj.__dict__ or hasattr(obj, field):
            return getattr(obj, field)
        if field == 'refs':
            return getattr(obj, 'references')
        return None
    except AttributeError:
        logger.error(f"ERROR: Field {field} is invalid")
        return None


def set_array(field, value, add=True):
    if isinstance(field, list):
        if add:
            if value not in field:
                field.append(value)
        else:
            if value in field:
                field.remove(value)


def update_vulnerability(api, vuln, key, value):
    if key == 'template':
        cwe = get_cwe(api, value)
        if cwe is None:
            logger.error(f"{value}: cwe not found")
            return False

        vuln.name = cwe.name
        vuln.description = cwe.description
        vuln.desc = cwe.description
        vuln.resolution = cwe.resolution

        logger.info(f"Applying template '{value}' to vulnerability '{vuln.name}' with id '{vuln.id}'")

    elif key == 'confirmed':
        value = value == 'True'
        vuln.confirmed = value
        logger.info(f"Changing property {key} to {value} in vulnerability '{vuln.name}' with id {vuln.id}")
    elif key == 'owned':
        value = value == 'True'
        vuln.owned = value
        logger.info(f"Changing property {key} to {value} in vulnerability '{vuln.name}' with id {vuln.id}")
    else:
        to_add = True
        if key.startswith('-'):
            key = key.strip('-')
            to_add = False

        is_custom_field = False
        if key in vuln.custom_fields:
            field = vuln.custom_fields
            is_custom_field = True
        else:
            field = get_field(vuln, key)

        if field is not None and is_custom_field is False:
            if isinstance(field, str):
                setattr(vuln, key, value)
                logger.info(
                    f"Changing property {key} to {value} in vulnerability '{vuln.name}' with id {vuln.id}")
            else:
                set_array(field, value, add=to_add)
                action = f'Adding {value} to {key} list in vulnerability {vuln.name} with id {vuln.id}'
                if not to_add:
                    action = 'Removing %s from %s list in vulnerability %s with id %s' % (
                        value, key, vuln.name, vuln.id)

                logger.info(action)

        if field is not None and is_custom_field is True:
            vuln.custom_fields[key] = value
            logger.info(
                f"Changing custom field {key} to {value} in vulnerability '{vuln.name}' with id {vuln.id}")

    api.update_vulnerability(vuln)

    logger.info("Done")
    return True


def update_service(api, service, key, value):
    if key == 'owned':
        value = value == 'True'
        service.owned = value
        logger.info(f"Changing property {key} to {value} in service '{service.name}' with id {service.id}")
    else:
        to_add = True
        if key.startswith('-'):
            key = key.strip('-')
            to_add = False

        field = get_field(service, key)
        if field is not None:
            if isinstance(field, str):
                setattr(service, key, value)
                logger.info(
                    f"Changing property {key} to {value} in service '{service.name}' with id {service.id}")
            else:
                set_array(field, value, add=to_add)
                action = f'Adding {value} to {key} list in service {service.name} with id {service.id}'
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
        logger.info(f"Changing property {key} to {value} in host '{host.name}' with id {host.id}")
    else:
        to_add = True
        if key.startswith('-'):
            key = key.strip('-')
            to_add = False

        field = get_field(host, key)
        if field is not None:
            if isinstance(field, str):
                setattr(host, key, value)
                logger.info(f"Changing property {key} to {value} in host '{host.name}' with id {host.id}")
            else:
                set_array(field, value, add=to_add)
                action = f'Adding {value} to {key} list in host {host.name} with id {host.id}'
                if not to_add:
                    action = 'Removing %s from %s list in host %s with id %s' % (
                        value, key, host.name, host.id)

                logger.info(action)
    api.update_host(host)

    logger.info("Done")
    return True


def get_parent(api, parent_tag):
    logger.debug("Getting parent")
    return api.get_filtered_services(id=parent_tag, name=parent_tag) or \
           api.get_filtered_hosts(id=parent_tag, name=parent_tag)


def filter_objects_by_parent(_objects, parent):
    objects = []
    parents = []
    if isinstance(parent, list):
        parents.extend(parent)
    else:
        parents.append(parent)
    for obj in _objects:
        for p in parents:
            if p.id == obj.parent_id:
                objects.append(obj)
    return objects


def evaluate_condition(model, condition):
    try:
        key, value = condition.split('=')
        if value == 'informational':
            value = 'info'
        if value == 'medium':
            value = 'med'
        value = value.replace('%', ' ')
        if key == 'regex':
            if re.match(value, model.name) is None:
                return False
            return True

        temp_value = getattr(model, key, None)
        #  fixme
        # if key in model.getMetadata():
        #     temp_value = model.getMetadata()[key]

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
    except Exception as error:
        logger.error(str(error))
        return False


def get_object(_models, obj):
    logger.debug("Getting object")
    objects = []
    if obj is None:
        if len(_models) > 0:
            objects.append(_models[-1])
            return objects
        return None

    items = obj.split()
    allow_old_option = '--old' in items
    if allow_old_option:
        items.remove('--old')
    for model in _models:
        if all([evaluate_condition(model, cond) for cond in items]):
            objects.append(model)
            if allow_old_option:
                break
    return objects


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
    value = value.replace('%', ' ')
    return value


def signal_handler(signal, frame):
    os.remove(".lock.pod")
    logger.info('Killed')
    sys.exit(0)


class Searcher:
    def __init__(self, api, mail_notification=None, tool_name='Searcher'):
        self.tool_name = tool_name
        self.api = api
        self.mail_notification = mail_notification
        self.rules = []

    def process(self, rules):
        if rules and validate_rules(rules):
            self.rules = [rule for rule in rules if 'disabled' not in rule or not rule['disabled']]

            self._process_vulnerabilities(self.rules)
            self._process_services(self.rules)
            self._process_hosts(self.rules)
            # TODO: FIX THIS

    def _process_vulnerabilities(self, rules):
        logger.debug("--> Start Process vulnerabilities")
        for rule_item in rules:
            logger.debug(f"Processing rule {rule_item['id']}")
            if rule_item['model'].lower() == 'vulnerability':
                count_values = 1
                values = [None]
                if 'values' in rule_item and len(rule_item['values']) > 0:
                    values = rule_item['values']
                    count_values = len(values)

                for index in range(count_values):
                    rule = replace_rule(rule_item, values[index])
                    vulnerabilities, parent = self._get_models(rule)
                    if 'fields' in rule:
                        self._process_models_by_similarity(vulnerabilities, rule)
                    else:
                        objects = self._get_object(rule)
                        objects = self.api.intersection(objects, vulnerabilities)
                        if objects is not None and len(objects) != 0:
                            if self._can_execute_action(rule, parent):
                                self._execute_action(objects, rule)

        logger.debug("<-- Finish Process vulnerabilities")

    def _process_services(self, rules):
        logger.debug("--> Start Process services")
        for rule_item in rules:
            logger.debug(f"Processing rule {rule_item['id']}")
            if rule_item['model'].lower() == 'service':
                count_values = 1
                values = [None]
                if 'values' in rule_item and len(rule_item['values']) > 0:
                    values = rule_item['values']
                    count_values = len(values)

                for index in range(count_values):
                    rule = replace_rule(rule_item, values[index])
                    services, parent = self._get_models(rule)
                    if 'fields' in rule:
                        self._process_models_by_similarity(services, rule)
                    else:
                        objects = self._get_object(rule)
                        objects = self.api.intersection(objects, services)
                        if objects is not None and len(objects) != 0:
                            if self._can_execute_action(rule, parent):
                                self._execute_action(objects, rule)

        logger.debug("<-- Finish Process services")

    def _process_hosts(self, rules):
        logger.debug("--> Start Process Hosts")
        for rule_item in rules:
            logger.debug(f"Processing rule {rule_item['id']}")
            if rule_item['model'].lower() == 'host':
                count_values = 1
                values = [None]
                if 'values' in rule_item and len(rule_item['values']) > 0:
                    values = rule_item['values']
                    count_values = len(values)

                for index in range(count_values):
                    rule = replace_rule(rule_item, values[index])
                    hosts, parent = self._get_models(rule)
                    if 'fields' in rule:
                        self._process_models_by_similarity(hosts, rule)
                    else:
                        objects = self._get_object(rule)
                        objects = self.api.intersection(objects, hosts)
                        if objects is not None and len(objects) != 0:
                            if self._can_execute_action(rule, parent):
                                self._execute_action(objects, rule)

        logger.debug("<-- Finish Process Hosts")

    def _fetch_objects(self, rule_model):
        if rule_model.lower() == 'vulnerability':
            return self.api.fetch_vulnerabilities()
        if rule_model.lower() == 'service':
            return self.api.fetch_services()
        if rule_model.lower() == 'host':
            return self.api.fetch_hosts()

    def _filter_objects(self, rule_model, **kwargs):
        if rule_model.lower() == 'vulnerability':
            return self.api.filter_vulnerabilities(**kwargs)
        if rule_model.lower() == 'service':
            return self.api.filter_services(**kwargs)
        if rule_model.lower() == 'host':
            return self.api.filter_hosts(**kwargs)

    def _get_models(self, rule):
        logger.debug("Getting models")
        if 'parent' in rule:
            parent = self._get_parent(rule['parent'])
            if parent is None:
                logger.warning(f"WARNING: Parent {rule['parent']} not found in rule {rule['id']} ")
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
            value = parse_value(value)
            kwargs[key] = value

        objects = self._filter_objects(rule['model'], **kwargs)
        if len(objects) == 0:
            objects = self._fetch_objects(rule['model'])
        return objects

    def _get_objects_by_parent(self, parent, objects_type):
        if isinstance(parent, Service) and objects_type.lower() == 'vulnerability':
            return parent.vulnerabilities + parent.web_vulnerabilities
        elif isinstance(parent, Host) and objects_type.lower() == 'vulnerability':
            return parent.vulnerabilities
        elif isinstance(parent, Host) and objects_type.lower() == 'service':
            return parent.services
        else:
            if parent.type.lower() == 'service' and objects_type.lower() == 'vulnerability':
                return self.api.filter_vulnerabilities(service_id=parent.id)
            elif parent.type.lower() == 'host' and objects_type.lower() == 'vulnerability':
                return self.api.filter_vulnerabilities(host_id=parent.id)
            elif parent.type.lower() == 'host' and objects_type.lower() == 'service':
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
            value = parse_value(value)
            kwargs[key] = value

        return len(self._filter_objects(rule['model'], **kwargs)) > 0

    def _execute_action(self, objects, rule):
        logger.info(f"Running actions of rule '{rule['id']}' :")
        actions = rule['actions']
        _objs_value = None
        if 'object' in rule:
            _objs_value = rule['object']
        command_start = datetime.utcnow()
        command_id = self.api.create_command(
            itime=time.mktime(command_start.timetuple()),
            params=self.rules,
            tool_name=self.tool_name
        )
        self.api.command_id = command_id
        for obj in objects:
            if hasattr(obj, 'type'):
                object_type = obj.type.capitalize()
            else:
                object_type = type(obj).__name__

            for action in actions:
                action = action.strip('--')
                array = action.split(':')
                command = array[0]
                expression = str(':').join(array[1:])

                if command == 'UPDATE':
                    array_exp = expression.split('=')
                    key = array_exp[0]
                    value = str('=').join(array_exp[1:])
                    if object_type in ['Vulnerabilityweb', 'Vulnerability_web', 'Vulnerability']:
                        self._update_vulnerability(obj, key, value)

                    if object_type == 'Service':
                        self._update_service(obj, key, value)

                    if object_type == 'Host':
                        self._update_host(obj, key, value)

                elif command == 'DELETE':
                    if object_type in ['Vulnerabilityweb', 'Vulnerability_web', 'Vulnerability']:
                        self.api.delete_vulnerability(obj.id)
                        logger.info(f"Deleting vulnerability '{obj.name}' with id '{obj.id}':")

                    elif object_type == 'Service':
                        self.api.delete_service(obj.id)
                        logger.info(f"Deleting service '{obj.name}' with id '{obj.id}':")

                    elif object_type == 'Host':
                        self.api.delete_host(obj.id)
                        logger.info(f"Deleting host '{obj.ip}' with id '{obj.id}':")
                else:
                    if self.mail_notification:
                        subject = 'Faraday searcher alert'
                        body = '%s %s have been modified by rule %s at %s' % (
                            object_type, obj.name, rule['id'], str(datetime.utcnow()))
                        self.mail_notification.send_mail(expression, subject, body)
                        logger.info(f"Sending mail to: '{expression}'")
                    else:
                        logger.warn("Searcher needs SMTP configuration to send mails")

        duration = (datetime.utcnow() - command_start).seconds
        self.api.close_command(self.api.command_id, duration)
        return True

    def _update_vulnerability(self, vuln, key, value):
        value = parse_value(value)
        if key == 'template':
            cwe = get_cwe(self.api, value)
            if cwe is None:
                logger.error(f"{value}: cwe not found")
                return False

            vuln.name = cwe.name
            vuln.description = cwe.description
            vuln.desc = cwe.description
            vuln.resolution = cwe.resolution

            logger.info(f"Applying template '{value}' to vulnerability '{vuln.name}' with id '{vuln.id}'")

        elif key == 'confirmed':
            value = value == 'True'
            vuln.confirmed = value
            logger.info(
                f"Changing property {key} to {value} in vulnerability '{vuln.name}' with id {vuln.id}")
        elif key == 'owned':
            value = value == 'True'
            vuln.owned = value
            logger.info(
                f"Changing property {key} to {value} in vulnerability '{vuln.name}' with id {vuln.id}")
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

            if key == 'refs':
                try:
                    vuln.references.add(value)
                except AttributeError:
                    vuln.refs.append(value)
            elif field:
                if not is_custom_field:
                    if isinstance(field, str):
                        setattr(vuln, key, value)
                        logger.info(
                            "Changing property %s to %s in vulnerability '%s' with id %s" % (
                                key, value, vuln.name, vuln.id))
                    else:
                        self.api.set_array(field, value, add=to_add, key=key, object=vuln)
                        action = 'Adding %s to %s list in vulnerability %s with id %s' % (
                            value, key, vuln.name, vuln.id)
                        if not to_add:
                            action = 'Removing %s from %s list in vulnerability %s with id %s' % (
                                value, key, vuln.name, vuln.id)

                        logger.info(action)

                else:
                    vuln.custom_fields[key] = value
                    logger.info(
                        "Changing custom field %s to %s in vulnerability '%s' with id %s" % (
                            key, value, vuln.name, vuln.id))

        result = self.api.update_vulnerability(vuln)
        if result is False:
            return result
        logger.info("Done")
        return True

    def _update_service(self, service, key, value):
        if key == 'owned':
            value = value == 'True'
            service.owned = value
            logger.info(
                f"Changing property {key} to {value} in service '{service.name}' with id {service.id}")
        else:
            to_add = True
            if key.startswith('-'):
                key = key.strip('-')
                to_add = False

            field = get_field(service, key)
            if field is not None:
                if isinstance(field, str):
                    setattr(service, key, value)
                    logger.info(
                        "Changing property %s to %s in service '%s' with id %s" % (
                            key, value, service.name, service.id))
                else:
                    self.api.set_array(field, value, add=to_add, key=key, object=service)
                    action = f'Adding {value} to {key} list in service {service.name} with id {service.id}'
                    if not to_add:
                        action = 'Removing %s from %s list in service %s with id %s' % (
                            value, key, service.name, service.id)

                    logger.info(action)

        self.api.update_service(service)

        logger.info("Done")
        return True

    def _update_host(self, host, key, value):
        if key == 'owned':
            value = value == 'True'
            host.owned = value
            logger.info(f"Changing property {key} to {value} in host '{host.ip}' with id {host.id}")
        else:
            to_add = True
            if key.startswith('-'):
                key = key.strip('-')
                to_add = False

            field = get_field(host, key)
            if field is not None:
                if isinstance(field, str):
                    setattr(host, key, value)
                    logger.info(f"Changing property {key} to {value} in host '{host.ip}' with id {host.id}")
                else:
                    self.api.set_array(field, value, add=to_add, key=key, object=host)
                    action = f'Adding {value} to {key} list in host {host.ip} with id {host.id}'
                    if not to_add:
                        action = 'Removing %s from %s list in host %s with id %s' % (
                            value, key, host.ip, host.id)

                    logger.info(action)
        self.api.update_host(host)

        logger.info("Done")
        return True

    def _process_models_by_similarity(self, _models, rule):
        logger.debug("--> Start Process models by similarity")
        for index_m1, m1 in zip(list(range(len(_models) - 1)), _models):
            for _, m2 in zip(list(range(index_m1 + 1, len(_models))), _models[index_m1 + 1:]):
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
                                    self._execute_action(_object, rule)
                            else:
                                self._execute_action(_object, rule)
        logger.debug("<-- Finish Process models by similarity")


@click.command()
@click.option('--workspace', required=True, prompt=True, help='Workspacer name')
@click.option('--server_address', required=True, prompt=True, help='Faraday server address')
@click.option('--user', required=True, prompt=True, help='')
@click.option('--password', required=True, prompt=True, hide_input=True, help='')
@click.option('--output', required=False, help='Choose a custom output directory', default='output')
@click.option('--email_sender', required=False)
@click.option('--smtp_username', required=False)
@click.option('--smtp_password', required=False)
@click.option('--mail_protocol', required=False)
@click.option('--port_protocol', required=False)
@click.option('--ssl', required=False)
@click.option('--log', required=False, default='debug')
@click.option('--rules', required=True, prompt=True, help='Filename with rules')
def main(workspace, server_address, user, password, output, email_sender,
         smtp_username, smtp_password, mail_protocol, port_protocol, ssl,
         log, rules):
    signal.signal(signal.SIGINT, signal_handler)

    loglevel = log
    with open(rules, 'r') as rules_file:
        try:
            rules = json.loads(rules_file.read())
        except Exception:
            print("Invalid rules file.")
            sys.exit(1)

    mail_notification = MailNotification(
        smtp_host=mail_protocol,
        smtp_sender=email_sender,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_port=port_protocol,
        smtp_ssl=ssl
    )

    for d in [output, 'log/']:  # TODO CHANGE THIS
        if not Path(d):
            Path(d).mkdir(parents=True)

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {loglevel}')

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
        logger.info(f'Searching objects into workspace {workspace} ')

        if not server_address.endswith('/'):
            server_address += '/'
        if not server_address.endswith('/_api'):
            server_address += '_api'

        api = Api(requests=requests, workspace=workspace, username=user, password=password, base=server_address)
        searcher = Searcher(api, mail_notification)
        searcher.process(rules)

        logger.info('Finished')
    except Exception as error:
        logger.exception(error)


if __name__ == "__main__":
    main()
# I'm Py3
