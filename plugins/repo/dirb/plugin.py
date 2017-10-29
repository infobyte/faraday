#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from plugins import core
import re
import socket

__author__ = "Federico Fernandez - @q3rv0"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Federico Fernandez"
__email__ = "fede.merlo26@gmail.com"
__status__ = "Development"


class dirbPlugin(core.PluginBase):

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "dirb"
        self.name = "Dirb"
        self.plugin_version = "0.0.1"
        self.version = "2.22"
        self.regexpUrl = r'((http[s]?)\:\/\/([\w\.]+)[.\S]+)'
        self._command_regex = re.compile(r'^(?:sudo dirb|dirb|\.\/dirb|sudo \.\/dirb)\s+(?:(http[s]?)\:\/\/([\w\.]+)[.\S]+)')
        self.text = []
        

    def getPort(self, host, proto):
        p = re.search(r"\:([0-9]+)\/", host)
        if p is not None:
            return p.group(1)
        elif proto == 'https':
            return 443
        else:
            return 80


    def getIP(self, host):
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            pass

        return ip


    def state(self, output):
        if output.find('COULDNT CONNECT') != -1:
            return "close"
        else:
            return "open"


    def pathsDirListing(self, output):
        data = []
        r = re.findall(self.regexpUrl + r"[\-\._\w\*\s]+\s+\(!\) WARNING: Directory IS LISTABLE",
                        output)
        for u in r:
            data.append(u[0])

        paths = "\n".join(data)
        return paths


    def note(self, output):
        dirs  = re.findall(r"==> DIRECTORY: "+self.regexpUrl, output)
        files = re.findall(r"\+ " + self.regexpUrl + r" \(.+\)", output)
        for d in dirs:
            self.text.append(d[0])

        for f in files:
            self.text.append(f[0])

        self.text = '\n'.join(self.text)


    def parseOutputString(self, output, debug=False):

        url = re.search(r"URL_BASE: " + self.regexpUrl, output)
        paths = self.pathsDirListing(output)
        status = self.state(output)
        self.note(output)

        if output.find('END_TIME') != -1 and url is not None:

            proto = url.group(2)
            domain = url.group(3)
            ip = self.getIP(domain)
            puerto = self.getPort(url.group(1), proto)

            host_id = self.createAndAddHost(ip)
            iface_id = self.createAndAddInterface(host_id, ip, ipv4_address = ip)
            serv_id  = self.createAndAddServiceToInterface(host_id, iface_id, proto, protocol = proto, ports =[puerto], status = status)

            if len(self.text) > 0:
                self.createAndAddNoteToService(host_id, serv_id, 'Url Fuzzing', self.text)

            if len(paths) > 0:
                self.createAndAddVulnWebToService(host_id, serv_id, "Directory Listing", severity = "med", website = domain, request = paths, method = "GET")

        return True



    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -oX parameter to get xml output to the command string that the
        user has set.
        """

        no_stop_on_warn_msg_re = r"\s+-w"
        arg_search = re.search(no_stop_on_warn_msg_re,command_string)
        extra_arg = ""
        if arg_search is None:
            extra_arg +=" -w"

        silent_mode_re = r"\s+-S"
        arg_search = re.search(silent_mode_re,command_string)
        if arg_search is None:
            extra_arg +=" -S"
        return "%s%s" % (command_string, extra_arg)

def createPlugin():
    return dirbPlugin()
