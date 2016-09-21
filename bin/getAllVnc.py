#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server.models import get_services

def main(workspace = ''):
    for service in get_services(workspace):
        if '5900' in service.ports:
            print(service.name)
