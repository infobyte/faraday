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
    default_regex = (
        r"ssl\-cert|ssl\-date|Traceroute Information|TCP\/IP Timestamps Supported"
        r"|OS Identification|Common Platform Enumeration")
    parser.add_argument('-y', '--yes', action="store_true")
    parser.add_argument('-r', '--regex', default=default_regex)
    parsed_args = parser.parse_args(args)
    if not parsed_args.yes:
        msg = ("Are you sure you want to delete all vulnerabilities "
               "matching the regex {} in the worspace {}? "
               "This action can't be undone [y/n] ".format(
                   parsed_args.regex, workspace))
        if raw_input(msg) not in ('y', 'yes'):
            return 1, None

    for vuln in models.get_all_vulns(workspace):
        if re.findall(parsed_args.regex, vuln.name, ) != []:
            print("Delete Vuln: " + vuln.name)
            models.delete_vuln(workspace, vuln.id)
    return 0, None
