#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import server, models

def main(workspace=''):
    
    for host in models.get_hosts(workspace):
        print('Delete Host:' + host.name)
        models.delete_host(workspace, host.id)