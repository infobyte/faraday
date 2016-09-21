#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from plugins import core
import re

__author__ = "Federico Fernandez - @q3rv0"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Federico Fernandez"
__email__ = "fede.merlo26@gmail.com"
__status__ = "Development"


class netdiscoverPlugin(core.PluginBase):

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id             = "netdiscover"
        self.name           = "Netdiscover"
        self.plugin_version = "0.0.1"
        self.version        = "1.0.0"
        self._command_regex = re.compile(r'^(sudo netdiscover|netdiscover).*?')
        self._completition   = {
                                ""               : "netdiscover [-i device] [-r range | -l file | -p] [-m file] [-s time] [-n node] [-c count] [-f] [-d] [-S] [-P] [-c]",
				"-i device"      : "your network device",
				"-r range"       : "scan a given range instead of auto scan. 192.168.6.0/24,/16,/8",
                                "-l file"        : "scan the list of ranges contained into the given file",
                                "-p passive mode": "do not send anything, only sniff",
                                "-m file"        : "scan the list of known MACs and host names",
                                "-F filter"      : "Customize pcap filter expression (default: \"arp\")",
                                "-s time"        : "time to sleep between each arp request (milliseconds)",
                                "-n node"        : "last ip octet used for scanning (from 2 to 253)",
                                "-c count"       : "number of times to send each arp reques (for nets with packet loss)",
                                "-f"             : "enable fastmode scan, saves a lot of time, recommended for auto",
                                "-d"             : "ignore home config files for autoscan and fast mode",
                                "-S"             : "enable sleep time supression between each request (hardcore mode)",
                                "-P"             : "print results in a format suitable for parsing by another program",
                                "-N"             : "Do not print header. Only valid when -P is enabled.",
                                "-L"             : "in parsable output mode (-P), continue listening after the active scan is completed"
			      }

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
    return netdiscoverPlugin()
