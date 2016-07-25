#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from plugins import core
from model import api
import re
import os
import pprint


__author__ = "Federico Kirschbaum"
__copyright__ = "Copyright 2013, Faraday Project"
__credits__ = ["Federico Kirschbaum"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Federico Kirschbaum"
__email__ = "fedek@infobytesec.com"
__status__ = "Development"


class CmdArpScanPlugin(core.PluginBase):
    """
    This plugin handles arp-scan command.
    Basically inserts into the tree the ouput of this tool
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "arp-scan"
        self.name = "arp-scan network scanner"
        self.plugin_version = "0.0.1"
        self.version = "1.8.1"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(
            r'^(sudo arp-scan|\.\/arp-scan|arp-scan).*?')
        self._host_ip = None
        self._port = "23"

    def parseOutputString(self, output, debug=False):

        host_info = re.search(
            r"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)", output)
        host_mac_addr = re.search(r"([\dA-F]{2}(?:[-:][\dA-F]{2}){5})", output)
        if host_info is None:
            api.devlog("No hosts detected")
        else:
            for line in output.split('\n'):
                vals = line.split("\t")

                if len(vals[0].split(".")) == 4:
                    host = vals[0]
                    h_id = self.createAndAddHost(host)
                    i_id = self.createAndAddInterface(
                        h_id, host, ipv4_address=host, mac=vals[1])
                    n_id = self.createAndAddNoteToHost(
                        h_id, "NIC VENDOR:", vals[2])

        return True

    def processCommandString(self, username, current_path, command_string):
        """
        """


def createPlugin():
    return CmdArpScanPlugin()
