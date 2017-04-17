#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from model.common import factory
from persistence.server import models

__description__ = 'Creates a new website vulnerability in a specified service'
__prettyname__ = 'Create Website Vulnerability'


def main(workspace='', args=None, parser=None):
    parser.add_argument('service', help='Parent service ID')
    parser.add_argument('name', help='Vulnerability name')
    parser.add_argument('--reference', help='Vulnerability reference', default='')  # Fixme

    parser.add_argument('--severity',
                        help='Vulnerability severity',
                        choices=['critical', 'high', 'med', 'low', 'info', 'unclassified'],
                        default='unclassified')

    parser.add_argument('--resolution', help='Resolution', default='')
    parser.add_argument('--description', help='Vulnerability description', default='')

    parser.add_argument('--website', help='Website', default='')
    parser.add_argument('--path', help='Path', default='')
    parser.add_argument('--request', help='Request', default='')
    parser.add_argument('--response', help='Response', default='')
    parser.add_argument('--method', help='Method', default='')
    parser.add_argument('--pname', help='pname', default='')  # FIXME
    parser.add_argument('--params', help='Parameters', default='')
    parser.add_argument('--query', help='Query', default='')
    parser.add_argument('--category', help='Category', default='')

    parser.add_argument('--confirmed', help='Is the vulnerability confirmed',
                        choices=['true', 'false'],
                        default='false')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    obj = factory.createModelObject(models.VulnWeb.class_signature, parsed_args.name, workspace,
                                    desc=parsed_args.description,
                                    ref=parsed_args.reference,
                                    severity=parsed_args.severity,
                                    resolution=parsed_args.resolution,

                                    website=parsed_args.website,
                                    path=parsed_args.path,
                                    request=parsed_args.request,
                                    response=parsed_args.response,
                                    method=parsed_args.method,
                                    pname=parsed_args.pname,
                                    params=parsed_args.params,
                                    query=parsed_args.query,
                                    category=parsed_args.category,

                                    confirmed=(parsed_args.confirmed == 'true'),
                                    parent_id=parsed_args.service
                                    )

    old = models.get_web_vuln(workspace, obj.getID())

    if old is None:
        if not parsed_args.dry_run:
            models.create_vuln_web(workspace, obj)
    else:
        print "A web vulnerability with ID %s already exists!" % obj.getID()
        return 2, None

    return 0, obj.getID()
