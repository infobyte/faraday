#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from faraday.client.model.common import factory
from faraday.client.persistence.server import models

__description__ = 'Creates a new host in current workspace'
__prettyname__ = 'Create Host'


def main(workspace='', args=None, parser=None):
    parser.add_argument('ip', help='Host IP')
    parser.add_argument('os', help='OS')

    parser.add_argument('mac', help='Interface MAC Address')

    parser.add_argument('--gateway', help='IPV4 or IPV6 Gateway', default='0.0.0.0')

    parser.add_argument('--netsegment', help='Network Segment', default='')


    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    params = {
        'ip': parsed_args.ip,
    }

    obj_host = factory.createModelObject(models.Host.class_signature,
                                        parsed_args.ip,
                                        workspace,
                                         os=parsed_args.os,
                                         mac=parsed_args.mac,
                                         network_segment=parsed_args.netsegment,
                                         parent_id=None)


    old_host = models.get_host(workspace, **params)

    if old_host is None:
        if not parsed_args.dry_run:
            models.create_host(workspace, obj_host)
            old_host = models.get_host(workspace, **params)
        else:
            return 0, None
    else:
        print("A host with ID %s already exists!" % old_host.getID())
        return 2, None

    return 0, old_host.getID()
