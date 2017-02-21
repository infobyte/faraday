#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

__description__ = 'Lists all scanned OSs'
__prettyname__ = 'Get All OSs'

from persistence.server import models


def main(workspace='', args=None, parser=None):
    parser.add_argument('-q', '--unique', help='Group OSs and print the total amount of hosts.', action='store_true')

    parsed_args = parser.parse_args(args)

    host_count = {}

    for host in models.get_hosts(workspace):

        if parsed_args.unique:
            if host.os in host_count:
                host_count[host.os] += 1
            else:
                host_count[host.os] = 1

        else:
            print host.os

    if parsed_args.unique:
        for host, count in host_count.items():
            print '%s\t(%d)' % (host, count)

    return 0, None
