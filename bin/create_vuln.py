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
    parser.add_argument('parent_type',
                        choices=['Host', 'Service'])
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

    obj = factory.createModelObject(models.Vuln.class_signature,
                                    parsed_args.name,
                                    workspace,
                                    ref=parsed_args.reference,
                                    severity=parsed_args.severity,
                                    resolution=parsed_args.resolution,
                                    confirmed=(parsed_args.confirmed == 'true'),
                                    desc=parsed_args.description,
                                    parent_id=parsed_args.parent,
                                    parent_type=parsed_args.parent_type.capitalize()
                                    )
    params = {
        'name': parsed_args.name,
        'description': parsed_args.description,
        'parent_type': parsed_args.parent_type.capitalize(),
        'parent': parsed_args.parent,
    }

    old = models.get_vulns(
        workspace,
        **params
    )

    if not old:
        if not parsed_args.dry_run:
            models.create_vuln(workspace, obj)
        old = models.get_vulns(
            workspace,
            **params
        )
    else:
        print "A vulnerability with ID %s already exists!" % old[0].getID()
        return 2, None

    return 0, old[0].getID()
