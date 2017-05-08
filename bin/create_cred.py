#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from model.common import factory
from persistence.server import models

__description__ = 'Creates new credentials'
__prettyname__ = 'Create Credentials'


def main(workspace='', args=None, parser=None):
    parser.add_argument('parent', help='Parent ID')
    parser.add_argument('name', help='Credential Name')
    parser.add_argument('username', help='Username')
    parser.add_argument('password', help='Password')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    obj = factory.createModelObject(models.Credential.class_signature, parsed_args.name, workspace,
                                    username=parsed_args.username,
                                    password=parsed_args.password,
                                    parent_id=parsed_args.parent
                                    )

    old = models.get_credential(workspace, obj.getID())

    if old is None:
        if not parsed_args.dry_run:
            models.create_credential(workspace, obj)
    else:
        print "A credential with ID %s already exists!" % obj.getID()
        return 2, None

    return 0, obj.getID()
