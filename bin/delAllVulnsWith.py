#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import re
from persistence.server.models import get_all_vulns, delete_vuln

def main(workspace = ''):

    regex = (
        r"ssl\-cert|ssl\-date|Traceroute Information|TCP\/IP Timestamps Supported"
        r"|OS Identification|Common Platform Enumeration")

    for vuln in get_all_vulns(workspace):
        if re.findall(regex, vuln.name, ) != []:
            print("Delete Vuln: " + vuln.name)
            delete_vuln(vuln.id)