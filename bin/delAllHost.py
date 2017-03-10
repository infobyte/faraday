#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import models

__description__ = 'Deletes all stored hosts'
__prettyname__ = 'Delete All Hosts'


def main(workspace='', args=None, parser=None):
    parser.add_argument('-y', '--yes', action="store_true")
    parsed_args = parser.parse_args(args)
    if not parsed_args.yes:
        msg = ("Are you sure you want to delete all hosts in the "
               "workspace {}? This action can't be undone [y/n] ".format(
                   workspace))
        if raw_input(msg) not in ('y', 'yes'):
            return 1, None
    for host in models.get_hosts(workspace):
        print('Delete Host:' + host.name)
        models.delete_host(workspace, host.id)
    return 0, None
