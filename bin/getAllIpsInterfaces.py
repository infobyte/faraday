#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import server, models

__description__ = "Get all scanned interfaces"
__prettyname__ = "Get All IPs Interfaces"


def main(workspace=''):
    for interface in models.get_interfaces(workspace):
        print(interface.ipv4['address'])
