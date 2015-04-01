#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
webs={}
for host in api.__model_controller.getAllHosts():

    for i in host.getAllInterfaces():
        for s in i.getAllServices():
            for p in s.getPorts():
                if str(p) == '5900':
                    webs[host.name]=1

for k,v in webs.iteritems():
     print k
