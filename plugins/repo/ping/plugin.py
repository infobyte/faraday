#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from plugins import core
import re

__author__ = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class CmdPingPlugin(core.PluginBase):
    """
    This plugin handles ping command.
    Basically detects if user was able to connect to a device
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "ping"
        self.name = "Ping"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        self._command_regex = re.compile(
            r'^(sudo ping|ping|sudo ping6|ping6).*?')

    def parseOutputString(self, output, debug=False):

        reg = re.search(r"PING ([\w\.-:]+)( |)\(([\w\.:]+)\)", output)
        if re.search("0 received|unknown host", output) is None and reg is not None:

            ip_address = reg.group(3)
            hostname = reg.group(1)

            h_id = self.createAndAddHost(ip_address)
            self.devlog('probando logging!!!!')
            self.log('INFO MESSAGE')
            self.log('ERROR MESSAGE', 'ERROR')
            if self._isIPV4(ip_address):
                i_id = self.createAndAddInterface(
                    h_id, ip_address, ipv4_address=ip_address, hostname_resolution=[hostname])
            else:
                self.createAndAddInterface(
                    h_id, ip_address, ipv6_address=ip_address, hostname_resolution=[hostname])

        return True

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
    return CmdPingPlugin()
