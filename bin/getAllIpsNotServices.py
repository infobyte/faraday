#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

# Get All IPs from targets without services
for host in api.__model_controller.getAllHosts():

    for i in host.getAllInterfaces():
        if not i.getAllServices():
            print host.name

