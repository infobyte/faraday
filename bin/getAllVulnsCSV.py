#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import re
vulns=""
for host in api.__model_controller.getAllHosts():
    hostnames=""
    for i in host.getAllInterfaces():
        for h in i._hostnames:
            hostnames+=","+h

    for v in host.getVulns():
        print host.name+"("+hostnames+")|0|"+v.name.encode("utf-8")+ "|"+re.sub("\n|\r",",",v.desc.encode("utf-8"))+"|"+str(v.severity)+"|"+str(v.id)

    for i in host.getAllInterfaces():
        for s in i.getAllServices():
            for v in s.getVulns():
                print host.name+"("+hostnames+")|"+str(s.getPorts()) + "|"+v.name.encode("utf-8")+ "|"+re.sub("\n|\r",",",v.desc.encode("utf-8"))+"|"+str(v.severity)+"|"+str(v.id)

