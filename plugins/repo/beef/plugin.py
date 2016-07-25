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
import os
import sys
import urllib2
import json

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class BeefPlugin(core.PluginBase):
    """
    Example plugin to parse beef output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Beef"
        self.name = "BeEF Online Service Plugin"
        self.plugin_version = "0.0.1"
        self.version = "0.4.4.9-alpha"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self.target = None
        self._command_regex = re.compile(r'^(beef|sudo beef|\.\/beef).*?')

        self.addSetting("Host", str, "http://127.0.0.1:3000/")
        self.addSetting(
            "Authkey", str, "c818c7798ae1da38b45a6406c8dd0d6d4d007098")
        self.addSetting("Enable", str, "0")

    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it from
        the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """
        try:
            f = urllib2.urlopen(self.getSetting(
                "Host") + "/api/hooks?token=" + self.getSetting("Authkey"))
            data = json.loads(f.read())
        except:
            api.devlog("[BeEF] - Connection with api")
            return

        if "hooked-browsers" in data:

            for t in ["online", "offlne"]:
                for h in data["hooked-browsers"][t]:

                    name = str(data["hooked-browsers"][t][h]['name'])
                    version = str(data["hooked-browsers"][t][h]['version'])
                    os = str(data["hooked-browsers"][t][h]['os'])
                    platform = str(data["hooked-browsers"][t][h]['platform'])
                    session = str(data["hooked-browsers"][t][h]['session'])
                    ip = str(data["hooked-browsers"][t][h]['ip'])
                    domain = str(data["hooked-browsers"][t][h]['domain'])
                    port = str(data["hooked-browsers"][t][h]['port'])
                    page_uri = str(data["hooked-browsers"][t][h]['page_uri'])

                    desc = "Client ip:" + ip + \
                        " has been injected with BeEF using the url:" + page_uri + "\n"

                    desc += "More information:"
                    desc += "\ntype:" + t
                    desc += "\nname:" + name
                    desc += "\nversion:" + version
                    desc += "\nos:" + os
                    desc += "\nplatform:" + platform
                    desc += "\nsession:" + session
                    desc += "\nip:" + ip
                    desc += "\ndomain:" + domain
                    desc += "\nport:" + port
                    desc += "\npage_uri:" + page_uri

                    h_id = self.createAndAddHost(ip)
                    v_id = self.createAndAddVulnToHost(
                        h_id,
                        "BeEF injected " + t + " session:" + session,
                        desc=desc,
                        ref=["http://http://beefproject.com/"],
                        severity=3)

    def processCommandString(self, username, current_path, command_string):
        return None

    def setHost(self):
        pass


def createPlugin():
    return BeefPlugin()

if __name__ == '__main__':
    parser = BeefXmlParser(sys.argv[1])
    for item in parser.items:
        if item.status == 'up':
            print item
