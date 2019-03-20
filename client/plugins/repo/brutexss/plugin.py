#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import re
import socket
from urlparse import urlparse

from faraday.client.plugins import core

__author__ = "Roberto Focke"
__copyright__ = "Copyright (c) 2017, Infobyte LLC"
__license__ = ""
__version__ = "1.0.0"


class brutexss (core.PluginBase):

        def __init__(self):
                core.PluginBase.__init__(self)
                self.id = "brutexss"
                self.name = "brutexss"
                self.plugin_version = "0.0.2"
                self.version = "1.0.0"
                self.protocol='tcp'

                self._command_regex = re.compile(r'^(sudo brutexss|brutexss|sudo brutexss\.py|brutexss\.py|python brutexss\.py|\.\/brutexss\.py).*?')

        def parseOutputString(self, output, debug=False):
                lineas = output.split("\n")
                parametro=[]
                found_vuln = False
                for linea in lineas:
                    if (linea.find("is available! Good!")>0):
                        print(linea)
                        url = re.findall('(?:[-\w.]|(?:%[\da-fA-F]{2}))+', linea)[0]
                        port = 80
                        if urlparse(url).scheme == 'https':
                            port = 443
                        netloc_splitted = urlparse(url).netloc.split(':')
                        if len(netloc_splitted) > 1:
                            port = netloc_splitted[1]
                    if ((linea.find("Vulnerable")>0) and (linea.find("No")<0)):
                        vuln_list = re.findall("\w+", linea)
                        if vuln_list[2]=="Vulnerable":
                                parametro.append(vuln_list[1])
                                found_vuln=len(parametro) > 0
                                host_id = self.createAndAddHost(url)
                                address=socket.gethostbyname(url)
                                interface_id = self.createAndAddInterface(host_id,address,ipv4_address=address,hostname_resolution=url)
                                service_id = self.createAndAddServiceToInterface(host_id,interface_id,self.protocol,'tcp',ports=[port],status='Open',version="",description="")
                if found_vuln:
                    self.createAndAddVulnWebToService(host_id,service_id,name="xss",desc="XSS",ref='',severity='med',website=url,path='',method='',pname='',params=''.join(parametro),request='',response='')

        def processCommandString(self, username, current_path, command_string):
                return None


def createPlugin():
    return brutexss()
