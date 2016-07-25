# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from plugins import core
import re

__author__ = "Andres Tarantini"
__copyright__ = "Copyright (c) 2015 Andres Tarantini"
__credits__ = ["Andres Tarantini"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Andres Tarantini"
__email__ = "atarantini@gmail.com"
__status__ = "Development"


class SSHDefaultScanPlugin(core.PluginBase):
    """
    Handle sshdefaultscan (https://github.com/atarantini/sshdefaultscan) output
    using --batch and --batch-template; supports --username and --password
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "sshdefaultscan"
        self.name = "sshdefaultscan"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        self._command_regex = re.compile(
            r'^(python sshdefaultscan.py|\./sshdefaultscan.py).*?')
        self._completition = {"--fast": "Fast scan mode"}

    def parseOutputString(self, output, debug=False):
        for line in [l.strip() for l in output.split("\n")]:
            output_rexeg_match = re.match(
                r".*:.*@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line)
            if output_rexeg_match:
                credentials, address = line.split("@")
                host = self.createAndAddHost(address)
                iface = self.createAndAddInterface(
                    host, address, ipv4_address=address)
                service = self.createAndAddServiceToInterface(
                    host, iface, "ssh", protocol="tcp", ports=22
                )
                username, password = credentials.split(":")
                cred = self.createAndAddCredToService(
                    host, service, username, password)
                vuln = self.createAndAddVulnToService(
                    host,
                    service,
                    "Default credentials",
                    desc="The SSH server have default credentials ({username}:{password})".format(
                        username=username,
                        password=password
                    ),
                    severity=3
                )

        return True

    def processCommandString(self, username, current_path, command_string):
        if "--batch" not in command_string:
            return "{command} --batch --batch-template {template}".format(
                command=command_string,
                template="{username}:{password}@{host}"
            )

        return None


def createPlugin():
    return SSHDefaultScanPlugin()
