#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from plugins import core 
import re

__author__ = "Roberto Focke"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__license__ = ""
__version__ = "1.0.0"

class hping3 (core.PluginBase):

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "hping3"
        self.name = "hping3"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        self.srv = {'21':'ftp',  '80':'http', '143':'imap', '1433':'mssql', '3306':'mysql','524':'ncp','110': 'nntp',
                    '5631':'pcanywhere', '110':'pop3', '5432':'postgres', '512':'rexec', '513':'rlogin', '514':'rsh',
                    '25':'smtp',  '161':'snmp', '22': 'ssh', '3690':'svn',
                    '23': 'telnet', '5900': 'vnc'}

        self._command_regex = re.compile(
            r'^(sudo hping3|hping3)\s+.*$')
        
    def parseOutputString(self, output, debug=False):
                
        reg = re.search(r"(\b\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\b)", output)
        ip_address=reg.group(1)
        hostname=output.split(" ")[1]
        host_id=self.createAndAddHost(hostname)
        if self._isIPV4(ip_address):
            
                i_id=self.createAndAddInterface(host_id, ip_address, ipv4_address=ip_address, hostname_resolution=hostname)
        
        else:
                i_id=self.createAndAddInterface(
                    host_id, ip_address, ipv6_addres=ip_address, hostname_resolution=hostname)
    
	'''
    procesar scaneos del tipo -S -p
    
    '''
	    if (re.match("HPING", output)):
		    sport=re.search(r"sport=(\d{1,6})",output)
        	ssport=[sport.group(1)]
       		reci=re.search(r"flags=(\w{2,3})",output)
        	servicio=self.srv[sport.group(1)]
                
		    if reci.group(1)=="SA":
                s_id=self.createAndAddServiceToInterface(host_id, i_id,servicio,protocol="tcp",ports=ssport,status="open") 
    '''
    procesar scaneo de tipo --scan -S -p 
    '''
        lineas=output.split("\n")
        for linea in lineas:
        
            if (re.match(" ",linea)):
                lista_recibida=re.findall("\w+",linea)
                servicio=lista_recibida[1]
                puerto=[lista_recibida[0]]
            
                if lista_recibida[2]=="S" and lista_recibida[3]=="A":
                    s_id=self.createAndAddServiceToInterface(host_id, i_id,servicio,protocol="tcp",ports=puerto,status="open") 
         
    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False
    def processCommandString(self, username, current_path, command_string):
        """
        """
        return None
        
def createPlugin():
    return hping3()
