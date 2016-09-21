#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server.models import get_credentials

def main(workspace = ''):

    for credential in get_credentials(workspace):
        print(credential.username + ' : ' + credential.password)