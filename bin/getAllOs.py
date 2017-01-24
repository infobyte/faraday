#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

__description__ = 'Get all OSs'

from persistence.server import server, models

def main(workspace=''):
    for host in models.get_hosts(workspace):
        print(host.os)