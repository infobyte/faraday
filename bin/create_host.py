#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from model.common import factory
from persistence.server import models

__description__ = 'Creates a new host in current workspace'
__prettyname__ = 'Create Host'


def main(workspace='', args=None, parser=None):
    parser.add_argument('name', help='Host name')
    parser.add_argument('os', help='OS')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    obj = factory.createModelObject(models.Host.class_signature, parsed_args.name,
                                    workspace, os=parsed_args.os, parent_id=None)

    old = models.get_host(workspace, obj.getID())

    if old is None:
        if not parsed_args.dry_run:
            models.create_host(workspace, obj)
    else:
        print "A host with ID %s already exists!" % obj.getID()
        return 2, None

    return 0, obj.getID()
