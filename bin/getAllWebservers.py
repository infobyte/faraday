#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import re
webs={}
for host in api.__model_controller.getAllHosts():

    for i in host.getAllInterfaces():
        for s in i.getAllServices():
            web=False
            if re.search("www|web|http|https",s.name):
                web=True

            if ['80','443','8080'] in s.getPorts():
                web=true

            for v in s.getVulns():
                if v.class_signature=="VulnerabilityWeb":
                    web=True
                    break
            if web==True:
                for p in s.getPorts():
                    webs["http://" + host.name+":"+str(p)+"/"]=1
                for n in s.getNotes():
                    if n.name =="website":
                        for wn in n.getNotes():
                            webs["http://" + wn.name+":"+str(p)+"/"]=1


for k,v in webs.iteritems():
    print k
                # if s.class_signature == "VulnerabilityWeb":

                # vulns=len(s.getVulns())
                # notes=len(s.getNotes())
                # if vulns >0 or notes>0:
                #     print "Service not delete" + s.name + "from int:" + i.name + " vulns:"+vulns+",notes:"+notes
                # else:
                #     print "delService" + s.name + "from int:" + i.name


