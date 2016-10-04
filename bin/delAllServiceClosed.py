#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import server, models

def main(workspace=''):
    
    for service in models.get_services(workspace):
        if service.status != 'open' or service.status != 'opened':
            print('Deleted service: ' + service.name)
            models.delete_service(workspace, service.id)