#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from plugins import core
import re
import os, json
import traceback

__author__ = "xtr4nge"
__copyright__ = "Copyright (c) 2016, FruityWiFi"
__credits__ = ["xtr4nge"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "xtr4nge"
__email__ = "@xtr4nge"
__status__ = "Development"

class FruityWiFiPlugin(core.PluginBase):
    """
    This plugin handles FruityWiFi clients.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "fruitywifi"
        self.name = "FruityWiFi"
        self.plugin_version = "0.0.1"
        self.version = "2.4"
        self.description = "http://www.fruitywifi.com"
        self.options = None
        self._current_output = None
        self.target = None
        
        self._command_regex = re.compile(
            r'^(fruitywifi).*?')
        
        self.addSetting("Token", str, "e5dab9a69988dd65e578041416773149ea57a054")
        self.addSetting("Server", str, "http://127.0.0.1:8000")
        self.addSetting("Severity", str, "high")
    
    def getSeverity(self, severity):
        if severity.lower() == "critical" or severity == "4":
            return 4
        elif severity.lower() == "high" or severity == "3":
            return 3
        elif severity.lower() == "med" or severity == "2":
            return 2
        elif severity.lower() == "low" or severity == "1":
            return 1
        elif severity.lower() == "info" or severity == "0":
            return 0
        else:
            return 5
    
    def createHostInterfaceVuln(self, ip_address, macaddress, hostname, desc, vuln_name, severity):
        h_id = self.createAndAddHost(ip_address)
        if self._isIPV4(ip_address):
            i_id = self.createAndAddInterface(
                h_id,
                ip_address,
                macaddress,
                ipv4_address=ip_address,
                hostname_resolution=[hostname]
                )
        else:
            self.createAndAddInterface(
                h_id, ip_address, ipv6_address=ip_address, hostname_resolution=[hostname])

        v_id = self.createAndAddVulnToHost(
                h_id,
                vuln_name,
                desc=desc,
                ref=["http://www.fruitywifi.com/"],
                severity=severity
                )
    
    def parseOutputString(self, output, debug=False):
        
        try:            
            output = json.loads(output)
            
            if len(output) > 0:
                
                if len(output[0]) == 3:
                    
                    severity = self.getSeverity(self.getSetting("Severity"))
                    
                    for item in output:
                        ip_address = item[0]
                        macaddress = item[1]
                        hostname = item[2]
                        vuln_name = "FruityWiFi"
                        severity = severity
            
                        desc = "Client ip: " + ip_address + \
                               " has been connected to FruityWiFi\n"
                        desc += "More information:"
                        desc += "\nname: " + hostname
                        
                        self.createHostInterfaceVuln(ip_address, macaddress, hostname, desc, vuln_name, severity)
            
                elif len(output[0]) == 5:
                    for item in output:
                        ip_address = item[0]
                        macaddress = item[1]
                        hostname = item[2]
                        vuln_name = item[3] 
                        severity = item[4]
            
                        desc = "Client ip: " + ip_address + \
                               " has been connected to FruityWiFi\n"
                        desc += "More information:"
                        desc += "\nname: " + hostname
            
                        self.createHostInterfaceVuln(ip_address, macaddress, hostname, desc, vuln_name, severity)
                        
        except:
            traceback.print_exc()
            
        return True

    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False

    def processCommandString(self, username, current_path, command_string, debug=False):
        """
        """        
        #params = command_string.replace("fruitywifi","")
        params = "-t %s -s %s" % (self.getSetting("Token"), self.getSetting("Server"))
        
        return "python " + os.path.dirname(__file__) + "/fruitywifi.py " + params
        #return None

def createPlugin():
    return FruityWiFiPlugin()
