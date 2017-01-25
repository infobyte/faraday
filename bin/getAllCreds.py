#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import server, models

__description__ = 'Get all stored credentials'
__prettyname__ = 'Get All Credentials'


def main(workspace=''):
    for credential in models.get_credentials(workspace):
        print(credential.username + ' : ' + credential.password)
