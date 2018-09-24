#!/usr/bin/env python
# -*- coding: utf-8 -*-

###
## Faraday Penetration Test IDE
## Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

import re
import logging
from rules import *

logger = logging.getLogger('Faraday searcher')

vfields = {
    'Vulnerability': ['name', 'desc', 'description', 'severity', 'data', 'confirmed', 'owned', 'owner', 'resolution',
                      'status'],

    'Service': ['name', 'description', 'owned', 'owner', 'parent', 'ports', 'protocol', 'status', 'version'],

    'Host': ['name', 'default_gateway', 'description', 'ipv4', 'ipv6', 'os', 'owned', 'owner']
}

commands = ['UPDATE', 'DELETE', 'ALERT', 'EXECUTE']


def validate_id(id_list, rule_id):
    return rule_id not in id_list


def validate_model(model):
    if model is not 'Host' and model is not 'Service' and model is not 'Vulnerability':
        return False
    return True


def validate_parent(parent):
    return parent != ''


def validate_fields(model, fields):
    if model in vfields and len(fields) != 0:
        for field in fields:
            if field not in vfields[model]:
                print "ERROR: The field '%s' doesn't exist in model '%s'" % (field, model)
                logger.error("The field '%s' doesn't exist in model '%s'" % (field, model))
                return False
        return True
    else:
        return False


def validate_indexer(indexer, allow_old_option=False):
    array = indexer.split()
    for item in array:
        array = item.split('=')
        if allow_old_option:
            if item != '--old' and len(array) != 2 or '' in array:
                logger.error("ERROR: '%s' must have 'field=value' or '--old'" % item)
                return False

        elif len(array) != 2 or '' in array:
            logger.error("ERROR: '%s' must have 'field=value' " % item)
            return False

    return True


def validate_object(obj):
    if obj == '':
        return False
    return validate_indexer(obj, allow_old_option=True)


def validate_conditions(conditions):
    if len(conditions) == 0:
        return False

    for cond in conditions:
        if not validate_indexer(cond):
            return False
    return True


def validate_action(actions):
    if len(actions) == 0:
        return False

    for action in actions:
        if not action.startswith('--UPDATE:') and not action.startswith('--ALERT:') and not action.startswith(
                '--EXECUTE:') and not action.startswith('--DELETE:'):
            return False

        if action.startswith('--UPDATE:'):
            expression = action.strip('--UPDATE:')
            if len(expression.split('=')) != 2 or expression.split('=')[0] == '' or expression.split('=')[1] == '':
                return False

        if action.startswith('--ALERT:'):
            expression = action.strip('--ALERT:')
            if expression == '' or re.match("^(.+\@.+\..+)$", expression) is None:
                return False

        if action.startswith('--EXECUTE:'):
            expression = action.strip('--EXECUTE:')
            if expression == '':
                return False

        if action.startswith('--DELETE:'):
            expression = action.strip('--DELETE:')
            if expression != '':
                return False

    return True


def validate(key, dictionary, validate_function=None, rule_id=None, mandatory=True, **args):
    if rule_id is None:
        if key not in dictionary:
            logger.error("ERROR: Key %s doesn't exist" % key)
            return False
        if not validate_function(args['id_list'], dictionary[key]):
            logger.error("ERROR: Key %s is repeated" % key)
            return False
    else:
        if key not in dictionary and mandatory:
            logger.error("ERROR: Key %s doesn't exist in rule: %s" % (key, rule_id))
            return False
        if key in dictionary:
            if key == 'fields':
                if not validate_function(args['model'], dictionary[key]):
                    logger.error("ERROR: Key %s has an invalid value in rule: %s" % (key, rule_id))
                    return False
                return True

            if not validate_function(dictionary[key]):
                logger.error("ERROR: Key %s has an invalid value in rule: %s" % (key, rule_id))
                return False

    return True


def validate_rules():
    logger.info('--> Validating rules ...')
    id_list = []
    for rule in rules:
        if not validate('id', rule, validate_id, id_list=id_list):
            return False
        rule_id = rule['id']
        id_list.append(rule_id)

        if not validate('model', rule, validate_model, rule_id):
            return False
        model = rule['model']

        if not validate('parent', rule, validate_parent, rule_id, mandatory=False):
            return False

        if not validate('fields', rule, validate_fields, rule_id, mandatory=False, model=model):
            return False

        if not validate('object', rule, validate_object, rule_id, mandatory=False):
            return False

        if not validate('conditions', rule, validate_conditions, rule_id, mandatory=False):
            return False

        if not validate('actions', rule, validate_action, rule_id):
            return False

    logger.info('<-- Rules OK')
    return True
