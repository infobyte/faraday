# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re

from plugins import core


__author__ = u"Andres Tarantini"
__copyright__ = u"Copyright (c) 2015 Andres Tarantini"
__credits__ = [u"Andres Tarantini"]
__license__ = u"MIT"
__version__ = u"0.0.1"
__maintainer__ = u"Andres Tarantini"
__email__ = u"atarantini@gmail.com"
__status__ = u"Development"


class DigPlugin(core.PluginBase):
    """
    Handle DiG (http://linux.die.net/man/1/dig) output
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = u"dig"
        self.name = u"DiG"
        self.plugin_version = u"0.0.1"
        self.version = u"9.9.5-3"
        self._command_regex = re.compile(r'^(dig).*?')

    def parseOutputString(self, output):
        # Ignore all lines that start with ";"
        parsed_output = [line for line in output.splitlines() if line and line[
            0] != u";"]
        if not parsed_output:
            return True

        # Parse results
        results = []
        answer_section_columns = [u"domain",
                                  u"ttl", u"class", u"type", u"address"]
        for line in parsed_output:
            results.append(dict(zip(answer_section_columns, line.split())))

        # Create hosts is results information is relevant
        for result in results:
            relevant_types = [u"A", u"AAAA"]
            if result.get(u"type") in relevant_types:
                ip_address = result.get(u"address")
                domain = result.get(u"domain")

                # Create host
                host = self.createAndAddHost(ip_address)

                # Create interface
                if len(ip_address.split(".")) == 4:
                    iface = self.createAndAddInterface(
                        host,
                        ip_address,
                        ipv4_address=ip_address,
                        hostname_resolution=[domain]
                    )
                else:
                    iface = self.createAndAddInterface(
                        host,
                        ip_address,
                        ipv6_address=ip_address,
                        hostname_resolution=[domain]
                    )

        return True


def createPlugin():
    return DigPlugin()
