#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import models

__description__ = 'Get all scanned IPs'
__prettyname__ = 'Get All IPs'


def main(workspace='', args=None, parser=None):
    for host in models.get_hosts(workspace):
        print(host.name)
    return 0, None
