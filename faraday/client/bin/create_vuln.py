#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from faraday.client.model.common import factory
from faraday.client.persistence.server import models
from faraday.client.persistence.server.server_io_exceptions import (
    CantCommunicateWithServerError,
    ConflictInDatabase
)

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

    try:
        models.create_vuln(workspace, obj)
    except ConflictInDatabase as ex:
        if ex.answer.status_code == 409:
            try:
                old_id = ex.answer.json()['object']['_id']
            except KeyError:
                print("Vulnerability already exists. Couldn't fetch ID")
                return 2, None
            else:
                print("A vulnerability with ID %s already exists!" % old_id)
                return 2, None
        else:
            print("Unknown error while creating the vulnerability")
            return 2, None
    except CantCommunicateWithServerError as ex:
        print("Error while creating vulnerability:", ex.response.text)
        return 2, None

    new = models.get_vulns(
        workspace,
        **params
    )

    return 0, new[0].getID()
