#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

for host in api.__model_controller.getAllHosts():
    for c in host.getCreds():
        print host.name+"|0|"+c.username+ "|"+c.password

    for i in host.getAllInterfaces():
        for s in i.getAllServices():
            for c in s.getCreds():
                print host.name+"|"+str(s.getPorts()) + "|"+c.username+ "|"+c.password

