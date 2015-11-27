#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import re
regex="ssl\-cert|ssl\-date|Traceroute Information|TCP\/IP Timestamps Supported|OS Identification|Common Platform Enumeration"
c=0
for host in api.__model_controller.getAllHosts():
    hostnames=""
    for v in host.getVulns():
        if re.match(regex,v.name) is not None:
            api.delVulnFromHost(v.id,host.id)
            c+=1

    for i in host.getAllInterfaces():
        for s in i.getAllServices():
            for v in s.getVulns():
                if re.match(regex,v.name) is not None:
                    api.delVulnFromService(v.id,host.id,s.id)
                    c+=1            

print "Vulnerabilities deleted %s" % c
