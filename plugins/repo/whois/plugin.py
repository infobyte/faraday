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
import os, socket
import pprint
current_path = os.path.abspath(os.getcwd())

__author__     = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__  = "Copyright (c) 2013, Infobyte LLC"
__credits__    = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__    = ""
__version__    = "1.0.0"
__maintainer__ = "Federico Kirschbaum"
__email__      = "fedek@infobytesec.com"
__status__     = "Development"

                           
                                                                     
                      

class CmdWhoisPlugin(core.PluginBase):
    """
    This plugin handles whois command.
    Basically detects if user was able to connect to a device
    """
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id              = "whois"
        self.name            = "Whois"
        self.plugin_version         = "0.0.1"
        self.version            = "5.0.20"
        self.framework_version  = "1.0.0"
        self.options         = None
        self._current_output = None
        self._command_regex  = re.compile(r'^whois.*?')
        self._host_ip        = None
        self._info           = 0;
        self._completition = {
            "":"whois [OPTION]... OBJECT...",
            "-l":"one level less specific lookup [RPSL only]",
            "-L":"find all Less specific matches",
            "-m":"find first level more specific matches",
            "-M":"find all More specific matches",
            "-c":"find the smallest match containing a mnt-irt attribute",
            "-x":"exact match [RPSL only]",
            "-d":"return DNS reverse delegation objects too [RPSL only]",
            "-i":"-i ATTR[,ATTR]...      do an inverse lookup for specified ATTRibutes",
            "-T":"-T TYPE[,TYPE]...      only look for objects of TYPE",
            "-K":"only primary keys are returned [RPSL only]",
            "-r":"turn off recursive lookups for contact information",
            "-R":"force to show local copy of the domain object even if it contains referral",
            "-a":"search all databases",
            "-s":"-s SOURCE[,SOURCE]...  search the database from SOURCE",
            "-g":"-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST",
            "-t":"-t TYPE request template for object of TYPE",
            "-v":"-v TYPE request verbose template for object of TYPE",
            "-q":"-q [version|sources|types]  query specified server info [RPSL only]",
            "-F":"fast raw output (implies -r)",
            "-h":"-h HOST connect to server HOST",
            "-p":"-p PORT connect to PORT",
            "-H":"hide legal disclaimers",
            "--verbose":"explain what is being done",
            "--help":"display this help and exit",
            "--version":"output version information and exit",
            }

        global current_path

                                  

    def resolve(self, host):
        try:
            return socket.gethostbyname(host)
        except:
            pass
        return host

    def parseOutputString(self, output, debug = False):
        matches = re.findall("Name Server:\s*(.*)\s*",output)
        for m in matches:
            m = m.strip()
            ip = self.resolve(m)
            h_id = self.createAndAddHost(ip, "os unknown")
            i_id = self.createAndAddInterface(h_id, ip, "00:00:00:00:00:00", ip, hostname_resolution=[m])
        return True    

    def processCommandString(self, username, current_path, command_string):
        """
        """
        return None

def createPlugin():
    return CmdWhoisPlugin()
