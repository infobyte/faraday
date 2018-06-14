#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from plugins import core
import re
import socket

__author__ = "Roberto Focke"
__copyright__ = "Copyright (c) 2017, Infobyte LLC"
__license__ = ""
__version__ = "1.0.0"


class brutexss (core.PluginBase):

	def __init__(self):

		core.PluginBase.__init__(self)
        	self.id = "brutexss"
        	self.name = "brutexss"
        	self.plugin_version = "0.0.1"
        	self.version = "1.0.0"
        	self.protocol='tcp'

        	self._command_regex = re.compile(r'^(sudo brutexss|brutexss|sudo brutexss\.py|brutexss\.py|python brutexss\.py|\.\/brutexss\.py).*?')
        

        

	def parseOutputString(self, output, debug=False):
		lineas = output.split("\n")
    		parametro=[]
		for linea in lineas:
        		if (linea.find("is available! Good!")>0):
            			url = re.findall('(?:[-\w.]|(?:%[\da-fA-F]{2}))+', linea)
            			print url
        		if ((linea.find("Vulnerable")>0) and (linea.find("No")<0)):
            			list = re.findall("\w+", linea)
            			if list[2]=="Vulnerable":
                			parametro.append(list[1])
                			j=len(parametro)
                			host_id = self.createAndAddHost(url[0])
                			address=socket.gethostbyname(url[0])
                			interface_id = self.createAndAddInterface(host_id,address,ipv4_address=address,hostname_resolution=url[0])
                			service_id = self.createAndAddServiceToInterface(host_id,interface_id,self.protocol,'tcp',ports=['80'],status='Open',version="",description="")
                if j:
		
			self.createAndAddVulnWebToService(host_id,service_id,name="xss",desc="XSS",ref='',severity='med',website=url[0],path='',method='',pname='',params=parametro,request='',response='')
                               
	def processCommandString(self, username, current_path, command_string):
        	return None


def createPlugin():
    return brutexss()
