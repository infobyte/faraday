#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from faraday.client.model.common import factory
from faraday.client.persistence.server import models

__description__ = 'Creates new credentials'
__prettyname__ = 'Create Credentials'


def main(workspace='', args=None, parser=None):
    parser.add_argument('parent', help='Parent ID')
    parser.add_argument('name', help='Credential Name')
    parser.add_argument('username', help='Username')
    parser.add_argument('password', help='Password')

    parser.add_argument('--parent_type',
                        help='Vulnerability severity',
                        choices=['Host', 'Service'],
                        default='unclassified')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')
    parsed_args = parser.parse_args(args)

    params = {
        'username': parsed_args.username,
    }

    if parsed_args.parent_type == 'Host':
        params.update({'host_id': parsed_args.parent})
    elif parsed_args.parent_type == 'Service':
        params.update({'service_id': parsed_args.parent})
    else:
        raise UserWarning('Credential only allow Host or Service as parent_type')

    obj = factory.createModelObject(models.Credential.class_signature,
                                    parsed_args.name,
                                    workspace,
                                    username=parsed_args.username,
                                    password=parsed_args.password,
                                    parent_type=parsed_args.parent_type,
                                    parent=parsed_args.parent
                                    )

    old = models.get_credential(workspace, **params)

    if old is None:
        if not parsed_args.dry_run:
            models.create_credential(workspace, obj)
            old = models.get_credential(workspace, **params)
    else:
        print("A credential with ID %s already exists!" % old.getID())
        return 2, None

    return 0, old.getID()
