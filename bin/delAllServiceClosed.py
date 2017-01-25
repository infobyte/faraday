#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import server, models

__description__ = 'Deletes all services with a non open port'
__prettyname__ = 'Delete All Service Closed'


def main(workspace=''):
    for service in models.get_services(workspace):
        if service.status != 'open' and service.status != 'opened':
            print('Deleted service: ' + service.name)
            models.delete_service(workspace, service.id)
