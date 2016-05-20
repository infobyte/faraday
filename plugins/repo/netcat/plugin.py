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

__author__     = "Ulisses Albuquerque"
__copyright__  = "Copyright (c) 2016, Securus Global"
__credits__    = ["Ulisses Albuquerque"]
__license__    = ""
__version__    = "1.0.0"
__maintainer__ = "Ulisses Albuquerque"
__email__      = "ulisses.albuquerque@securusglobal.com"
__status__     = "Development"


class CmdNetcatPlugin(core.PluginBase):
    """
    This plugin handles ping command.
    Basically detects if user was able to connect to a device
    """
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id              = "netcat"
        self.name            = "Netcat"
        self.plugin_version  = "0.0.1"
        self.version         = "1.0.0"
        self._command_regex  = re.compile(r'^(?:.*\|)?\s*(?:nc|netcat|nc.openbsd|nc.traditional)\s+.*$')
        self._completition = {
            "": "[-bhklnrtuvCz] [-c shell] [-e filename] [-g gateway] [-G num] [-i secs] [-o file] [-p port] [-q secs] [-s addr] [-T tos] [-w secs]",
            "-c": "shell",
            "-e": "filename",
            "-b": "allow broadcasts",
            "-g": "gateway",
            "-G": "num",
            "-h": "this cruft",
            "-i": "secs",
            "-k": "set keepalive option on socket",
            "-l": "listen mode, for inbound connects",
            "-n": "numeric-only IP addresses, no DNS",
            "-o": "file",
            "-p": "port",
            "-r": "randomize local and remote ports",
            "-q": "secs",
            "-s": "addr",
            "-T": "tos",
            "-t": "answer TELNET negotiation",
            "-u": "UDP mode",
            "-v": "verbose [use twice to be more verbose]",
            "-w": "secs",
            "-C": "Send CRLF as line-ending",
            "-z": "zero-I/O mode [used for scanning]",
        }

    def resolveHost(self, host):
        """
        The use of gethostbyname/gethostbyaddr here is questionable, but it is
        the easiest way to sort out the discrepancies between the output
        formats of both versions of netcat
        """
        if re.search(r'^\d{1,3}(?:\.\d{1,3}){3}', host) is not None:
            try:
                result = socket.gethostbyaddr(host)
                return (host, result[0])
            except:
                return (host, None)
        else:
            try:
                result = socket.gethostbyname(host)
                return (result, host)
            except:
                return (None, host)

    def addEntry(self, attr_dict):
        """
        Because output differs between both versions of netcat, and because
        the user might use the -n parameter which disables name resolution,
        we need to check if the values we are getting are hostnames or IP
        addresses
        """
        ip_address, hostname = self.resolveHost(attr_dict['host'])

        # When service does not match anything in /etc/services, we get those
        if attr_dict['service'] == '*' or attr_dict['service'] == '?':
            attr_dict['service'] = 'unknown'

        if 'protocol' not in attr_dict:
            attr_dict['protocol'] = 'tcp'

        h_id = self.createAndAddHost(hostname)
        i_id = self.createAndAddInterface(h_id, ip_address, ipv4_address = ip_address)
        s_id = self.createAndAddServiceToInterface(h_id, i_id, attr_dict['service'],
            protocol = attr_dict['protocol'], ports = [ int(attr_dict['port']) ])

    def matchInOutput(self, regexp, output):
        """
        We take a split & filter approach to matching our regexps to the
        command output
        """
        mapped_list = map(lambda s: re.search(regexp, s), re.split(r'(\r|\n)', output))
        filtered_list = filter(lambda s: s is not None, mapped_list)

        if len(filtered_list) > 0:
            return filtered_list[0]
        else:
            return None

    def parseOutputString(self, output, debug = False):
        """
        There are at least two variants of netcat, the OpenBSD version and the
        'traditional' version. The verbose output differs between them, so we
        will try to cover both cases.
        """
        nc_bsd_rx = re.compile(r'^Connection\s+to\s+(?P<host>\S+)\s+(?P<port>\d+)\s+port\s+\[(?P<protocol>tcp|udp)/(?P<service>[^\]]+)\]\s+succeeded.*')
        nc_sys_rx = re.compile(r'^(?P<host>\S+)\s+\[(?P<address>[0-9\.]+)\]\s+(?P<port>\d+)\s+\((?P<service>[^)]+)\)\s+open.*')

        nc_bsd_match = self.matchInOutput(nc_bsd_rx, output)
        if nc_bsd_match is not None:
            self.addEntry(nc_bsd_match.groupdict())

        nc_sys_match = self.matchInOutput(nc_sys_rx, output)
        if nc_sys_match is not None:
            self.addEntry(nc_sys_match.groupdict())

        return True

    def processCommandString(self, username, current_path, command_string):
        """
        We need to use '-v' because otherwise netcat does not provide any
        output to indicate whether a connection has been successful; our
        regexp can certainly be improved, because we might get '-v' combined
        with other parameters, like in "nc -nv"
        """
        if re.search(r'(nc|netcat)[^\d|\|]*-v', command_string) is None:
            return re.sub(r'(nc(?:\.traditional|\.openbsd)?|netcat)', r'\1 -v', command_string)

        return command_string

def createPlugin():
    return CmdNetcatPlugin()
