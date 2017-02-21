#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from model.common import factory
from persistence.server import models

__description__ = 'Creates a new service in a specified interface'
__prettyname__ = 'Create Service'


def main(workspace='', args=None, parser=None):
    parser.add_argument('interface_id', help='Interface ID')
    parser.add_argument('name', help='Interface Name')
    parser.add_argument('ports', help='Service ports, as a comma separated list')
    parser.add_argument('--protocol', help='Service protocol', default='tcp')
    parser.add_argument('--status', help='Service status', default='running')
    parser.add_argument('--version', help='Service version', default='unknown')
    parser.add_argument('--description', help='Service description', default='')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    ports = filter(None, parsed_args.ports.split(','))

    obj = factory.createModelObject(models.Service.class_signature, parsed_args.name, workspace,
                                    protocol=parsed_args.protocol,
                                    ports=ports,
                                    status=parsed_args.status,
                                    version=parsed_args.version,
                                    description=parsed_args.description,
                                    parent_id=parsed_args.interface_id
                                    )

    old = models.get_service(workspace, obj.getID())

    if old is None:
        if not parsed_args.dry_run:
            models.create_service(workspace, obj)
    else:
        print "A service with ID %s already exists!" % obj.getID()
        return 2, None

    return 0, obj.getID()
