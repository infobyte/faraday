#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import server, models

__description__ = 'Get all hosts with an open HTTP/HTTPS port'
__prettyname__ = 'Get All HTTP Servers'


def main(workspace=''):
    ports = [80, 443, 8080, 8443]
    for service in models.get_services(workspace):
        for port in ports:
            if port in service.ports:
                print(service.name)
