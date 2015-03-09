#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import with_statement
from plugins import core
from model import api
import re
import os, socket
import pprint
current_path = os.path.abspath(os.getcwd())

__author__     = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__  = "Copyright (c) 2013, Infobyte LLC"
__credits__    = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__    = ""
__version__    = "1.0.0"
__maintainer__ = "Facundo de Guzmán"
__email__      = "fdeguzman@ribadeohacklab.com.ar"
__status__     = "Development"

                           
                                                                     
                      

class TelnetRouterPlugin(core.PluginBase):
    """
    This plugin handles telnet command.
    Basically detects if user was able to connect to a device
    """
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id              = "Telnet"
        self.name            = "Telnet"
        self.plugin_version         = "0.0.1"
        self.version            ="0.17"
        self.framework_version  = "1.0.0"
        self.options         = None
        self._current_output = None
        self._command_regex  = re.compile(r'^telnet.*?')
        self._host_ip        = None
        self._host           = []
        self._port        = "23"
        self._completition = {
            "":"telnet [-468ELadr] [-S tos] [-b address] [-e escapechar] [-l user] [-n tracefile] [host [port]]",
            "-4":"Force IPv4 address resolution.",
            "-6":"Force IPv6 address resolution.",
            "-8":"Request 8-bit operation. This causes an attempt to negotiate the TELNET BINARY option for both input and output. By default telnet is not 8-bit clean.",
            "-E":"Disables the escape character functionality; that is, sets the escape character to ``no character''.",
            "-L":"Specifies an 8-bit data path on output.  This causes the TELNET BINARY option to be negotiated on just output.",
            "-a":"Attempt automatic login.  Currently, this sends the user name via the USER variable of the ENVIRON option if supported by the remote system. The username is retrieved via getlogin(3).",
            "-b":"-b &lt;address&gt; Use bind(2) on the local socket to bind it to a specific local address.",
            "-d":"Sets the initial value of the debug toggle to TRUE.",
            "-r":"Emulate rlogin(1).  In this mode, the default escape character is a tilde. Also, the interpretation of the escape character is changed: an escape character followed by a dot causes telnet to disconnect from the remote host. A ^Z instead of a dot suspends telnet, and a ^] (the default telnet escape character) generates a normal telnet prompt. These codes are accepted only at the beginning of a line.",
            "-S":"-S &lt;tos&gt;  Sets the IP type-of-service (TOS) option for the telnet connection to the value tos.",
            "-e":"-e &lt;escapechar&gt; Sets the escape character to escapechar. If no character is supplied, no escape character will be used.  Entering the escape character while connected causes telnet to drop to command mode.",
            "-l":"-l &lt;user&gt; Specify user as the user to log in as on the remote system. This is accomplished by sending the specified name as the USER environment variable, so it requires that the remote system support the TELNET ENVIRON option. This option implies the -a option, and may also be used with the open command.",
            "-n":"-n &lt;tracefile&gt; Opens tracefile for recording trace information.  See the set tracefile command below.",
            }

        global current_path

    def resolve(self, host):
        try:
            return socket.gethostbyname(host)
        except:
            pass
        return host

    def parseOutputString(self, output, debug = False):

        host_info = re.search(r"Connected to (.+)\.", output)
        
        hostname=host_info.group(1)
        ip_address = self.resolve(hostname)
        
        if host_info is not None:
            h_id = self.createAndAddHost(ip_address)
            i_id = self.createAndAddInterface(h_id, ip_address, ipv4_address=ip_address, hostname_resolution=hostname)
            s_id = self.createAndAddServiceToInterface(h_id, i_id, self._port,
                                               "tcp",
                                               ports = [self._port],
                                               status = "open")
        return True


    def processCommandString(self, username, current_path, command_string):
        
        count_args = command_string.split()
        
        c=count_args.__len__()
        self._port="23"
        if re.search("[\d]+",count_args[c-1]):
            self._port = count_args[c-1]


def createPlugin():
    return TelnetRouterPlugin()
