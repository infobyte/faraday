#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server.models import get_services

def main(workspace = ''):

    ports = ['80', '443', '8080']
    for service in get_services(workspace):
        for port in ports:
            if port in service.ports:
                print(service.name)
