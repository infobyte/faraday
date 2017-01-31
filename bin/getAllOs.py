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
    parser.add_argument('-q', '--unique', help='Only print and OS once', action='store_true')

    parsed_args = parser.parse_args(args)

    printed = set()

    for host in models.get_hosts(workspace):

        if not parsed_args.unique or (parsed_args.unique and host.os not in printed):
            print(host.os)

        if parsed_args.unique:
            printed.add(host.os)

    return 0, None
