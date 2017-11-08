#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from model.common import factory
from persistence.server import models

__description__ = 'Creates a new host and interface in current workspace'
__prettyname__ = 'Create Host and Interface'


def main(workspace='', args=None, parser=None):
    parser.add_argument('host_name', help='Host name')
    parser.add_argument('os', help='OS')

    parser.add_argument('interface_name', help='Interface Name')
    parser.add_argument('mac', help='Interface MAC Address')

    parser.add_argument('--ipv4address', help='IPV4 Address', default='0.0.0.0')
    parser.add_argument('--ipv4gateway', help='IPV4 Gateway', default='0.0.0.0')
    parser.add_argument('--ipv4mask', help='IPV4 Mask', default='0.0.0.0')
    parser.add_argument('--ipv4dns', help='IPV4 DNS, as a comma separated list', default='[]')

    parser.add_argument('--ipv6address', help='IPV6 Address', default='0000:0000:0000:0000:0000:0000:0000:0000')
    parser.add_argument('--ipv6prefix', help='IPV6 Prefix', default='00')
    parser.add_argument('--ipv6gateway', help='IPV4 Gateway', default='0000:0000:0000:0000:0000:0000:0000:0000')
    parser.add_argument('--ipv6dns', help='IPV6 DNS, as a comma separated list', default='')

    parser.add_argument('--netsegment', help='Network Segment', default='')
    parser.add_argument('--hostres', help='Hostname Resolution', default='')


    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    obj_host = factory.createModelObject(models.Host.class_signature, parsed_args.host_name,
                                    workspace, os=parsed_args.os, parent_id=None)


    old_host = models.get_host(workspace, obj_host.getID())

    if old_host is None:
        if not parsed_args.dry_run:
            models.create_host(workspace, obj_host)
    else:
        print "A host with ID %s already exists!" % obj_host.getID()
        return 2, None



    obj_interface = factory.createModelObject(models.Interface.class_signature, parsed_args.interface_name, workspace,
                                    mac=parsed_args.mac,
                                    ipv4_address=parsed_args.ipv4address,
                                    ipv4_mask=parsed_args.ipv4mask,
                                    ipv4_gateway=parsed_args.ipv4gateway,
                                    ipv4_dns=parsed_args.ipv4dns,
                                    ipv6_address=parsed_args.ipv6address,
                                    ipv6_prefix=parsed_args.ipv6prefix,
                                    ipv6_gateway=parsed_args.ipv6gateway,
                                    ipv6_dns=parsed_args.ipv6dns,
                                    network_segment=parsed_args.netsegment,
                                    hostname_resolution=parsed_args.hostres,
                                    parent_id= obj_host.getID() )

    old_interface = models.get_interface(workspace, obj_interface.getID())

    if old_interface is None:
        if not parsed_args.dry_run:
            models.create_interface(workspace, obj_interface)
    else:
        print "An interface with ID %s already exists!" % obj_interface.getID()
        return 2, None

    return 0, obj_interface.getID()
