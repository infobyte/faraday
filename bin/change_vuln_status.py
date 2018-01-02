#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from __future__ import print_function
from persistence.server.server_io_exceptions  import ResourceDoesNotExist
from persistence.server import models
from utils.user_input import query_yes_no

__description__ = 'Changes Vulns Status (to closed)'
__prettyname__ = 'Change Vulns Status (to closed)'

def main(workspace='', args=None, parser=None):

    parser.add_argument('-y', '--yes', action="store_true")
    parsed_args = parser.parse_args(args)

    try:
        vulns = models.get_all_vulns(workspace)
    except ResourceDoesNotExist:
        print ("Invalid workspace name: ", workspace)
        return 1, None

    if not parsed_args.yes:
        if not query_yes_no("Are you sure you want to change the status to closed of all the vulns in workspace %s" % workspace, default='no'):
            return 1, None

    count = 0
    for vuln in vulns:
        old_status = vuln.status

        # Valid status
        if vuln.status != "closed":

            vuln.status = "closed"
            count += 1

            if vuln.class_signature == "Vulnerability":
                models.update_vuln(workspace, vuln)

            elif vuln.class_signature == "VulnerabilityWeb":
                models.update_vuln_web(workspace, vuln)

            print (vuln.name, ": Status changed from", old_status,"to closed successfully")

    print ("End of process:", count, "vulnerabilities changed to closed")
    return 0, None
