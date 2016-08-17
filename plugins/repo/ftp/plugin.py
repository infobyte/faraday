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
import socket

current_path = os.path.abspath(os.getcwd())

__author__ = "Javier Victor Mariano Bruno"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Javier Victor Mariano Bruno"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Javier Victor Mariano Bruno"
__email__ = "mbruno@infobytesec.com"
__status__ = "Development"


class CmdFtpPlugin(core.PluginBase):
    """
    This plugin handles ftp command.
    Basically detects if user was able to connect to a device
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "ftp"
        self.name = "Ftp"
        self.plugin_version = "0.0.1"
        self.version = "0.17"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(r'^ftp.*?')
        self._host_ip = None
        self._port = "21"
        self._info = 0
        self._version = None

        global current_path

    def resolve(self, host):
        try:
            return socket.gethostbyname(host)
        except:
            pass
        return host

    def parseOutputString(self, output, debug=False):

        host_info = re.search(r"Connected to (.+)\.", output)
        banner = re.search("220?([\w\W]+)$", output)
        if re.search("Connection timed out", output) is None and host_info is not None:
            hostname = host_info.group(1)
            ip_address = self.resolve(hostname)
            self._version = banner.groups(0) if banner else ""
            if debug:
                print ip_address

            h_id = self.createAndAddHost(ip_address)

            i_id = self.createAndAddInterface(
                h_id,
                ip_address,
                ipv4_address=ip_address,
                hostname_resolution=hostname)

            s_id = self.createAndAddServiceToInterface(
                h_id,
                i_id,
                "ftp",
                "tcp",
                ports=[self._port],
                status="open")

        if debug is True:
            api.devlog("Debug is active")

        return True

    def processCommandString(self, username, current_path, command_string):
        """
        """
        count_args = command_string.split()

        c = count_args.__len__()
        self._port = "21"
        if re.search("[\d]+", count_args[c - 1]):
            self._port = count_args[c - 1]

        return None


def createPlugin():
    return CmdFtpPlugin()
