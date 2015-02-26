#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

for host in api.__model_controller.getAllHosts():
    for i in host.getAllInterfaces():
        for h in i._hostnames:
            print h
