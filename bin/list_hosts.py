#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from persistence.server import models

__description__ = 'List hosts'
__prettyname__ = 'List Hosts'


def main(workspace='', args=None, parser=None):
    parser.add_argument('os', nargs='*', help='List of OSs to filter for', default=[]),

    parsed_args = parser.parse_args(args)

    for host in models.get_hosts(workspace):
        print '%s\t%s' % (host.name, host.os)

    return 0, None
