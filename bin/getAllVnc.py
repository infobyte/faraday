#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import server, models

__description__ = 'Get all hosts with an open VNC port'
__prettyname__ = 'Get All VNC'


def main(workspace=''):
    for service in models.get_services(workspace):
        if 5900 in service.ports:
            print(service.name)
