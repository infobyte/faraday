#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from model.common import factory
from persistence.server import models

__description__ = 'Creates a new vulnerability'
__prettyname__ = 'Create Vulnerability'


def main(workspace='', args=None, parser=None):
    parser.add_argument('parent', help='Parent ID')
    parser.add_argument('name', help='Vulnerability Name')
    parser.add_argument('--reference', help='Vulnerability reference', default='')  # Fixme

    parser.add_argument('--severity',
                        help='Vulnerability severity',
                        choices=['critical', 'high', 'med', 'low', 'info', 'unclassified'],
                        default='unclassified')

    parser.add_argument('--resolution', help='Resolution', default='')
    parser.add_argument('--confirmed', help='Is the vulnerability confirmed',
                        choices=['true', 'false'],
                        default='false')
    parser.add_argument('--description', help='Vulnerability description', default='')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    obj = factory.createModelObject(models.Vuln.class_signature, parsed_args.name, workspace,
                                    name=parsed_args.name,
                                    ref=parsed_args.reference,
                                    severity=parsed_args.severity,
                                    resolution=parsed_args.resolution,
                                    confirmed=(parsed_args.confirmed == 'true'),
                                    desc=parsed_args.description,
                                    parent_id=parsed_args.parent
                                    )

    old = models.get_vuln(workspace, obj.getID())

    if old is None:
        if not parsed_args.dry_run:
            models.create_vuln(workspace, obj)
    else:
        print "A vulnerability with ID %s already exists!" % obj.getID()
        return 2, None

    return 0, obj.getID()
