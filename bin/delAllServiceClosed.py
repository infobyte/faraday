#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

for host in api.__model_controller.getAllHosts():

    for i in host.getAllInterfaces():
        for s in i.getAllServices():
            if s.getStatus() != "open":
                print "delService" + s.name + "from int:" + i.name
                api.delServiceFromInterface(host.id,i.id,s.id)


