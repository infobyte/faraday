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
#    print "hydra -l '' -p 'telecom' -w 10 telnet://"+k+":23"





# 200.61.47.65
# 200.45.69.29
# 200.61.47.217
# 200.61.47.121
# 200.45.69.17
# 200.61.47.129
# 200.61.47.113
# 200.61.47.9
# 190.221.164.65
# 200.61.47.146
# 186.153.146.227
# 200.61.47.177
# 200.61.47.17
# 200.61.47.33
# 200.45.69.30
# 200.61.47.179
# 200.61.47.233
# 200.61.47.41
# 200.61.47.221
# 200.61.47.220
