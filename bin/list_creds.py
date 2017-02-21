#!/usr/bin/env python2.7

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.server import models

__description__ = 'Get all stored credentials'
__prettyname__ = 'List Credentials'


def main(workspace='', args=None, parser=None):
    parsed_args = parser.parse_args(args)

    for credential in models.get_credentials(workspace):
        print(credential.username + ' : ' + credential.password)
    return 0, None
