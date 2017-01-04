# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import re
import socket
from os import path
from plugins import core
from urlparse import urlparse

__author__ = "Andres Tarantini"
__copyright__ = "Copyright (c) 2015 Andres Tarantini"
__credits__ = ["Andres Tarantini"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Andres Tarantini"
__email__ = "atarantini@gmail.com"
__status__ = "Development"


class PeepingTomPlugin(core.PluginBase):
    """
    Handle PeepingTom (https://bitbucket.org/LaNMaSteR53/peepingtom) output
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "peepingtom"
        self.name = "PeepingTom"
        self.plugin_version = "0.0.1"
        self.version = "02.19.15"
        self._command_regex = re.compile(
            r'^(python peepingtom.py|\./peepingtom.py).*?')
        self._path = None

    def parseOutputString(self, output):
        # Find data path
        data_path_search = re.search(r"in '(.*)\/'", output)
        print data_path_search
        if not data_path_search:
            # No data path found
            return True

        # Parse "peepingtom.html" report and extract results
        data_path = data_path_search.groups()[0]
        html = open(path.join(self._path, data_path, "peepingtom.html")).read()
        for url in re.findall(r'href=[\'"]?([^\'" >]+)', html):
            if "://" in url:
                url_parsed = urlparse(url)
                address = socket.gethostbyname(url_parsed.netloc)
                host = self.createAndAddHost(address)
                iface = self.createAndAddInterface(
                    host, address, ipv4_address=address)
                service = self.createAndAddServiceToInterface(host, iface, "http", protocol="tcp", ports=[80])
                self.createAndAddNoteToService(
                    host,
                    service,
                    'screenshot',
                    path.join(
                        self._path,
                        data_path_search.groups()[0],
                        "{}.png".format(url.replace(
                            "://", "").replace("/", "").replace(".", ""))
                    )
                )

        return True

    def processCommandString(self, username, current_path, command_string):
        self._path = current_path
        return None


def createPlugin():
    return PeepingTomPlugin()
