#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''
import re
from faraday.client.persistence.server import models

__description__ = "Get all scanned interfaces"
__prettyname__ = "Get All IPs Interfaces"


def main(workspace='', args=None, parser=None):
    ip_regex = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    not_matching_count = 0
    for host in models.get_hosts(workspace):
        if re.match(ip_regex, host.ip):
            print(host.ip)
        else:
            not_matching_count += 1
    if not_matching_count:
        print('Hosts that has invalid ip addresses {0}'.format(not_matching_count))

    return 0, None
