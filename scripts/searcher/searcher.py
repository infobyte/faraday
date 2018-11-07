#!/usr/bin/env python
# -*- coding: utf-8 -*-

###
## Faraday Penetration Test IDE
## Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

import argparse
import os
import signal
import smtplib
import sqlite3
import subprocess
import sys
from datetime import datetime
from difflib import SequenceMatcher
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
import json
from config.configuration import getInstanceConfiguration
from persistence.server import models
from persistence.server import server
from persistence.server.server import login_user
from persistence.server.server_io_exceptions import ResourceDoesNotExist, ConflictInDatabase
from validator import *
import urlparse


logger = logging.getLogger('Faraday searcher')

reload(sys)
sys.setdefaultencoding("utf-8")

CONF = getInstanceConfiguration()


def send_mail(to_addr, subject, body):
    from_addr = 'faraday.searcher@gmail.com'
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))
    try:
        server_mail = smtplib.SMTP('smtp.gmail.com', 587)
        server_mail.starttls()
        server_mail.login(from_addr, "faradaySearcher.2018")
        text = msg.as_string()
        server_mail.sendmail(from_addr, to_addr, text)
        server_mail.quit()
    except Exception as error:
        logger.error("Error: unable to send email")
        logger.error(error)


def compare(a, b):
    return SequenceMatcher(None, a, b).ratio()


def get_cwe(data, _server='http://127.0.0.1:5985/'):
    logger.debug("Getting vulnerability templates from %s " % _server)
    try:
        url = urlparse.urljoin(_server, "_api/v2/vulnerability_template/")
        session_cookie = CONF.getDBSessionCookies()
        response = requests.request("GET", url, cookies=session_cookie)
        if response.status_code == 200:
            templates = json.loads(response.content)
            cwe = None
            for row in templates['rows']:
                doc = row['doc']
                _id = doc['_id']
                name = doc['name']
                description = doc['description']
                resolution = doc['resolution']
                if str(_id) == data or name == data:
                    cwe = {
                        'id': _id,
                        'name': name,
                        'description': description,
                        'resolution': resolution
                    }
                    break
            return cwe
        elif response.status_code == 401:
            logger.error('You are not authorized to get the vulnerability templates')
            return None
        else:
            logger.error('We can\'t get the vulnerability templates')
            return None

    except Exception as error:
        logger.error(error)
        return None


def is_same_level(model1, model2):
    return model1.parent_id == model2.parent_id


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


def process_models_by_similarity(ws, _models, rule, _server):
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
                                execute_action(ws, _object, rule, _server)
                        else:
                            execute_action(ws, _object, rule, _server)
    logger.debug("<-- Finish Process models by similarity")


def insert_rule(_id, command, obj, selector, fields=None, key=None, value=None, output_file='output/searcher.db'):
    logger.debug("Inserting rule %s into SQlite database ..." % _id)
    conn = sqlite3.connect(output_file)
    conn.text_factory = str
    try:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS rule (
                                id TEXT,
                                model TEXT NOT NULL,
                                fields TEXT,
                                command TEXT NOT NULL,
                                object_id TEXT NOT NULL,
                                object_name TEXT NOT NULL,
                                key TEXT,
                                value TEXT,
                                created TEXT NOT NULL,
                                selector TEXT)''')

        created = str(datetime.now())
        rule = (_id, obj.class_signature, fields, command, obj.id, obj.name, key, value, created, selector)
        cursor.execute('INSERT INTO rule VALUES (?,?,?,?,?,?,?,?,?,?)', rule)
        conn.commit()
        conn.close()
        logger.debug("Done")
    except sqlite3.Error as e:
        conn.close()
        logger.error(e)


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


def update_vulnerability(ws, vuln, key, value, _server):
    if key == 'template':
        cwe = get_cwe(value, _server)
        if cwe is None:
            logger.error("%s: cwe not found" % value)
            return False

        vuln.name = cwe['name']
        vuln.description = cwe['description']
        vuln.desc = cwe['description']
        vuln.resolution = cwe['resolution']

        logger.info("Applying template '%s' to vulnerability '%s' with id '%s'" % (value, vuln.name, vuln.id))

    elif key == 'confirmed':
        value = value == 'True'
        vuln.confirmed = value
        logger.info("Changing property %s to %s in vulnerability '%s' with id %s" % (key, value, vuln.name, vuln.id))
    elif key == 'owned':
        value = value == 'True'
        vuln.owned = value
        logger.info("Changing property %s to %s in vulnerability '%s' with id %s" % (key, value, vuln.name, vuln.id))
    else:
        to_add = True
        if key.startswith('-'):
            key = key.strip('-')
            to_add = False

        field = get_field(vuln, key)
        if field is not None:
            if isinstance(field, str) or isinstance(field, unicode):
                setattr(vuln, key, value)
                logger.info(
                    "Changing property %s to %s in vulnerability '%s' with id %s" % (key, value, vuln.name, vuln.id))
            else:
                set_array(field, value, add=to_add)
                action = 'Adding %s to %s list in vulnerability %s with id %s' % (value, key, vuln.name, vuln.id)
                if not to_add:
                    action = 'Removing %s from %s list in vulnerability %s with id %s' % (
                        value, key, vuln.name, vuln.id)

                logger.info(action)

    try:
        if vuln.class_signature == "Vulnerability":
            models.update_vuln(ws, vuln)

        elif vuln.class_signature == "VulnerabilityWeb":
            models.update_vuln_web(ws, vuln)

    except ConflictInDatabase:
        logger.error("There was a conflict trying to save '%s' with ID: %s" % (vuln.name, vuln.id))
        return False
    except Exception as error:
        logger.error(error)
        return False

    logger.info("Done")
    return True


def update_service(ws, service, key, value):
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
            if isinstance(field, str) or isinstance(field, unicode):
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
    try:
        models.update_service(ws, service, "")
    except Exception as error:
        logger.error(error)
        return False

    logger.info("Done")
    return True


def update_host(ws, host, key, value):
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
            if isinstance(field, str) or isinstance(field, unicode):
                setattr(host, key, value)
                logger.info("Changing property %s to %s in host '%s' with id %s" % (key, value, host.name, host.id))
            else:
                set_array(field, value, add=to_add)
                action = 'Adding %s to %s list in host %s with id %s' % (value, key, host.name, host.id)
                if not to_add:
                    action = 'Removing %s from %s list in host %s with id %s' % (
                        value, key, host.name, host.id)

                logger.info(action)
    try:
        models.update_host(ws, host, "")
    except Exception as error:
        logger.error(error)
        return False

    logger.info("Done")
    return True


def get_parent(ws, parent_tag):
    logger.debug("Getting parent")
    try:
        parent = models.get_host(ws, parent_tag) or models.get_service(ws, parent_tag)
    except ResourceDoesNotExist:
        parent = models.get_hosts(ws, name=parent_tag) or models.get_services(ws, name=parent_tag)
        if len(parent) == 0:
            return None

    return parent


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
        if value not in temp_value and str(value) not in temp_value and int(value) not in temp_value:
            return False
        return True

    if isinstance(temp_value, bool):
        if value == 'True' and not temp_value:
            return False
        if value == 'False' and temp_value:
            return False
        return True

    if value.encode("utf-8") != temp_value.encode("utf-8"):
        return False
    return True


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


def get_models(ws, objects, rule):
    logger.debug("Getting models")
    if 'parent' in rule:
        parent = get_parent(ws, rule['parent'])
        if parent is None:
            logger.warning("WARNING: Parent %s not found in rule %s " % (rule['parent'], rule['id']))
            return objects
        return filter_objects_by_parent(objects, parent)
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


def execute_action(ws, objects, rule, _server):
    logger.info("Running actions of rule '%s' :" % rule['id'])
    actions = rule['actions']
    _objs_value = None
    if 'object' in rule:
        _objs_value = rule['object']

    for obj in objects:
        for action in actions:
            action = action.strip('--')
            command, expression = action.split(':')

            if command == 'UPDATE':
                key, value = expression.split('=')
                if obj.class_signature == 'VulnerabilityWeb' or obj.class_signature == 'Vulnerability':
                    if update_vulnerability(ws, obj, key, value, _server):
                        insert_rule(rule['id'], command, obj, _objs_value, fields=None, key=key, value=value)

                if obj.class_signature == 'Service':
                    update_service(ws, obj, key, value)

                if obj.class_signature == 'Host':
                    update_host(ws, obj, key, value)

            elif command == 'DELETE':
                if obj.class_signature == 'VulnerabilityWeb':
                    models.delete_vuln_web(ws, obj.id)
                    logger.info(" Deleting vulnerability web '%s' with id '%s':" % (obj.name, obj.id))
                    insert_rule(rule['id'], command, obj, _objs_value)

                elif obj.class_signature == 'Vulnerability':
                    models.delete_vuln(ws, obj.id)
                    logger.info("Deleting vulnerability '%s' with id '%s':" % (obj.name, obj.id))

                elif obj.class_signature == 'Service':
                    models.delete_service(ws, obj.id)
                    logger.info("Deleting service '%s' with id '%s':" % (obj.name, obj.id))

                elif obj.class_signature == 'Host':
                    models.delete_host(ws, obj.id)
                    logger.info("Deleting host '%s' with id '%s':" % (obj.name, obj.id))

            elif command == 'EXECUTE':
                if subprocess.call(expression, shell=True, stdin=None) is 0:
                    logger.info("Running command: '%s'" % expression)
                    insert_rule(rule['id'], command, obj, _objs_value, fields=None, key=None, value=expression)
                else:
                    logger.error("Operation fail running command: '%s'" % expression)
                    return False
            else:
                subject = 'Faraday searcher alert'
                body = '%s %s have been modified by rule %s at %s' % (
                    obj.class_signature, obj.name, rule['id'], str(datetime.now()))
                send_mail(expression, subject, body)
                insert_rule(rule['id'], command, obj, _objs_value, fields=None, key=None, value=expression)
                logger.info("Sending mail to: '%s'" % expression)
    return True


def process_vulnerabilities(ws, vulns, _server):
    logger.debug("--> Start Process vulnerabilities")
    for rule in rules:
        if rule['model'] == 'Vulnerability':
            vulnerabilities = get_models(ws, vulns, rule)
            if 'fields' in rule:
                process_models_by_similarity(ws, vulnerabilities, rule, _server)
            else:
                _objs_value = None
                if 'object' in rule:
                    _objs_value = rule['object']
                objects = get_object(vulnerabilities, _objs_value)
                if objects is not None and len(objects) != 0:
                    if 'conditions' in rule:
                        if can_execute_action(vulnerabilities, rule['conditions']):
                            execute_action(ws, objects, rule, _server)
                    else:
                        execute_action(ws, objects, rule, _server)
    logger.debug("<-- Finish Process vulnerabilities")


def process_services(ws, services, _server):
    logger.debug("--> Start Process services")
    for rule in rules:
        if rule['model'] == 'Service':
            services = get_models(ws, services, rule)
            if 'fields' in rule:
                process_models_by_similarity(ws, services, rule, _server)
                pass
            else:
                _objs_value = None
                if 'object' in rule:
                    _objs_value = rule['object']
                objects = get_object(services, _objs_value)
                if objects is not None and len(objects) != 0:
                    if 'conditions' in rule:
                        if can_execute_action(services, rule['conditions']):
                            execute_action(ws, objects, rule, _server)
                    else:
                        execute_action(ws, objects, rule, _server)
    logger.debug("<-- Finish Process services")


def process_hosts(ws, hosts, _server):
    logger.debug("--> Start Process Hosts")
    for rule in rules:
        if rule['model'] == 'Host':
            hosts = get_models(ws, hosts, rule)
            if 'fields' in rule:
                process_models_by_similarity(ws, hosts, rule, _server)
                pass
            else:
                _objs_value = None
                if 'object' in rule:
                    _objs_value = rule['object']
                objects = get_object(hosts, _objs_value)
                if objects is not None and len(objects) != 0:
                    if 'conditions' in rule:
                        if can_execute_action(hosts, rule['conditions']):
                            execute_action(ws, objects, rule, _server)
                    else:
                        execute_action(ws, objects, rule, _server)
        logger.debug("<-- Finish Process Hosts")


def lock_file(lockfile):
    if os.path.isfile(lockfile):
        return False
    else:
        f = open(lockfile, 'w')
        f.close()
        return True


def signal_handler(signal, frame):
    os.remove(".lock.pod")
    logger.info('Killed')
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Search duplicated objects on Faraday')
    parser.add_argument('-w', '--workspace', help='Search duplicated objects into this workspace', required=True)
    parser.add_argument('-s', '--server', help='Faraday server', required=False, default="http://127.0.0.1:5985/")
    parser.add_argument('-u', '--user', help='Faraday user', required=False, default="")
    parser.add_argument('-p', '--password', help='Faraday password', required=False, default="")
    parser.add_argument('-o', '--output', help='Choose a custom output directory', required=False)
    parser.add_argument('-l', '--log', help='Choose a custom log level', required=False)
    args = parser.parse_args()

    lockf = ".lock.pod"
    if not lock_file(lockf):
        print ("You can run only one instance of searcher (%s)" % lockf)
        exit(0)

    workspace = ''
    if args.workspace:
        workspace = args.workspace
    else:
        print("You must enter a workspace in command line, please use --help to read more")
        os.remove(lockf)
        exit(0)

    _server = 'http://127.0.0.1:5985/'
    if args.server:
        _server = args.server

    _user = 'faraday'
    if args.user:
        _user = args.user

    _password = 'changeme'
    if args.password:
        _password = args.password

    output = 'output/'
    if args.output:
        output = args.output

    loglevel = 'debug'
    if args.log:
        loglevel = args.log

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
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

    try:
        session_cookie = login_user(_server, _user, _password)
        if not session_cookie:
            raise UserWarning('Invalid credentials!')
        else:
            CONF.setDBUser(_user)
            CONF.setDBSessionCookies(session_cookie)

        server.AUTH_USER = _user
        server.AUTH_PASS = _password
        server.SERVER_URL = _server
        server.FARADAY_UP = False

        logger.info('Started')
        logger.info('Searching objects into workspace %s ' % workspace)

        logger.debug("Getting hosts ...")
        hosts = models.get_hosts(workspace)

        logger.debug("Getting services ...")
        services = models.get_services(workspace)

        logger.debug("Getting vulnerabilities ...")
        vulns = models.get_all_vulns(workspace)

        if validate_rules():
            process_vulnerabilities(workspace, vulns, _server)
            process_services(workspace, services, _server)
            process_hosts(workspace, hosts, _server)

        # Remove lockfile
        os.remove(lockf)

        logger.info('Finished')

    except ResourceDoesNotExist:
        logger.error("Resource not found")
        os.remove(lockf)
        exit(0)

    except Exception as errorMsg:
        logger.error(errorMsg)
        os.remove(lockf)
        exit(0)


if __name__ == "__main__":
    main()
