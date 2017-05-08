#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import models

__description__ = 'List all scanned IPs'
__prettyname__ = 'Get All IPs'


def main(workspace='', args=None, parser=None):
    parser.add_argument('-s', '--sorted', help='Print a sorted list of IPs.', action='store_true')

    parsed_args = parser.parse_args(args)

    ips = []

    for host in models.get_hosts(workspace):

        if parsed_args.sorted:
            ips += [host.name]
        else:
            print(host.name)

    if parsed_args.sorted:
        print '\n'.join(sorted(ips))

    return 0, None
