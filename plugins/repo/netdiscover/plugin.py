#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from plugins import core
import pprint
import re

__author__ = "Federico Fernandez - @q3rv0"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Federico Fernandez"
__email__ = "fede.merlo26@gmail.com"
__status__ = "Development"

class NetdiscoverPlugin(core.PluginBase):

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id             = "Netdiscover"
        self.name           = "netdiscover"
        self.plugin_version = "0.0.1"
        self.version        = "1.0.0"
        self._command_regex = re.compile(r'^(sudo netdiscover|netdiscover).*?')

    def parseOutputString(self, output, debug=False):
        #regexp get ip, mac and hostname
        reg = re.findall(r"(([0-9]+\.?){4})\s+(([0-9a-f]+\:?){6})((\s+[0-9]+){2})(.*)", output)
        
        if output.find('Finished!') != -1 and len(reg) > 0:

            for stdout in reg:
                ip_address = stdout[0]
                mac        = stdout[2]
                hostname   = stdout[6].strip()

                h_id = self.createAndAddHost(ip_address)
                self.createAndAddInterface(h_id, ip_address, ipv4_address=ip_address, mac=mac, hostname_resolution=[hostname])

        return True

    def processCommandString(self, username, current_path, command_string):
        return None


def createPlugin():
    return NetdiscoverPlugin()
