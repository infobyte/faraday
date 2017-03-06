#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import re
from persistence.server import models

__description__ = "Delete all vulnerabilities matched with regex"
__prettyname__ = "Delete all vulnerabilities with (...)"


def main(workspace='', args=None, parser=None):
    regex = (
        r"ssl\-cert|ssl\-date|Traceroute Information|TCP\/IP Timestamps Supported"
        r"|OS Identification|Common Platform Enumeration")

    for vuln in models.get_all_vulns(workspace):
        if re.findall(regex, vuln.name, ) != []:
            print("Delete Vuln: " + vuln.name)
            models.delete_vuln(workspace, vuln.id)
    return 0, None
