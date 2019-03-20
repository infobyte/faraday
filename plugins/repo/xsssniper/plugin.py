#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import re
import socket
from faraday.client.plugins import core

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
            parametro=[]
            lineas = output.split("\n")
            aux = 0
            for linea in lineas:
                if not linea:
                    continue
                linea = linea.lower()
                if ((linea.find("target:")>0)):
                        url = re.findall('(?:[-\w.]|(?:%[\da-fA-F]{2}))+', linea)
                        host_id = self.createAndAddHost(url[3])
                        address=socket.gethostbyname(url[3])
                        interface_id = self.createAndAddInterface(host_id,address,ipv4_address=address,hostname_resolution=url[3])
                if ((linea.find("method")>0)):
                        list_a = re.findall("\w+", linea)
                        metodo= list_a[1]
                if ((linea.find("query string:")>0)):
                        lista_parametros=linea.split('=')
                        aux=len(lista_parametros)
                if ((linea.find("param:")>0)):
                        list2= re.findall("\w+",linea)
                        parametro.append(list2[1])
                        service_id = self.createAndAddServiceToInterface(host_id,interface_id,self.protocol,'tcp',ports=['80'],status='Open',version="", description="")
            if aux !=0:
                self.createAndAddVulnWebToService(host_id,service_id,name="xss",desc="XSS",ref='',severity='med',website=url[0],path='',method=metodo,pname='',params=''.join(parametro),request='',response='')

        def processCommandString(self, username, current_path, command_string):
                return None


def createPlugin():
    return xsssniper()


if __name__ == '__main__':
    plugin_xss = xsssniper()
    with open('xsssniper_out', 'r') as xsssniper_file:
        plugin_xss.parseOutputString(xsssniper_file.read())
