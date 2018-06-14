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

class xsssniper (core.PluginBase):

        def __init__(self):

                core.PluginBase.__init__(self)
                self.id = "xsssniper"
                self.name = "xsssniper"
                self.plugin_version = "0.0.1"
                self.version = "1.0.0"
                self.protocol="tcp"
                self._command_regex = re.compile(r'^(sudo xsssniper|xsssniper|sudo xsssniper\.py|xsssniper\.py|sudo python xsssniper\.py|.\/xsssniper\.py|python xsssniper\.py)')

        def parseOutputString(self, output, debug=False):
		j=0
		parametro=[]
                lineas = output.split("\n")
                for linea in lineas:
                        if ((linea.find("--[!] Target:")>0)):
                                url = re.findall('(?:[-\w.]|(?:%[\da-fA-F]{2}))+', linea)
                                print url
			
			
			
                        if ((linea.find("Method")>0)):
                                list = re.findall("\w+", linea)
				print list[1]
                                metodo= list[1]
			if ((linea.find("Query String:")>0)):
				lista_parametros=linea.split('=')
				print lista_parametros
				aux=len(lista_parametros)
				print aux			
                        if ((linea.find("--[!] Param:")>0)):
                                list2= re.findall("\w+",linea)
				print list2[1]
                                parametro.append(list2[1])
                                host_id = self.createAndAddHost(url[3])
				address=socket.gethostbyname(url[3])
               			interface_id = self.createAndAddInterface(host_id,address,ipv4_address=address,hostname_resolution=url[3])
                        	service_id = self.createAndAddServiceToInterface(host_id,interface_id,self.protocol,'tcp',ports=['80'],status='Open',version="", description="")
		if aux !=0:
			print "entro al if"
			print parametro
		
			self.createAndAddVulnWebToService(host_id,service_id,name="xss",desc="XSS",ref='',severity='med',website=url[0],path='',method=metodo,pname='',params=parametro,request='',response='')
                       
		
	def processCommandString(self, username, current_path, command_string):
		return None


def createPlugin():
    return xsssniper()
