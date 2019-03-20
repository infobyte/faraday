#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import csv
import StringIO
from faraday.client.plugins import core

def calculate_severity(number):

    if number is None:
        return "info"

    number = float(number)

    # Based in CVSS V2
    if number >= 0 and number <= 3.9:
        return "low"
    elif number >= 4.0 and number <= 6.9:
        return "med"
    elif number >= 7.0 and number <= 10:
        return "high"

class Ip360Parser:

    def __init__(self, csv_content):
        self.csv_content = StringIO.StringIO(csv_content.decode('ascii', 'ignore'))
        self.csv_reader = csv.DictReader(self.csv_content, delimiter=',', quotechar='"')

    def parse(self):

        result = []
        for row in self.csv_reader:

            host = {
                "name": row.get("IP"),
                "os": row.get("OS")
            }

            interface = {
                "name": row.get("IP"),
                "hostname_resolution": [row.get("NetBIOS Name")],
                "network_segment": row.get("NetBIOS Domain"),
            }

            service = {"port": row.get("Port")}

            vulnerability = {
                "name": row.get("Vulnerability"),
                "description": row.get("Description"),
                "resolution": row.get("Remediation"),
                "ref": [
                    row.get("CVE"),
                    "Vuln ID: " + row.get("Vulnerability ID"),
                    "Risk: " + row.get("Risk"),
                    "Skill: " + row.get("Skill"),
                    "CVSS V2: " + row.get("CVSS V2"),
                    "CVSS V3: " + row.get("CVSS V3")],
                "severity": row.get("CVSS V2")
            }

            result.append((host, interface, service, vulnerability))

        return result

class Ip360Plugin(core.PluginBase):
    """
    Example plugin to parse Ip360 output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Ip360"
        self.name = "Ip360 CSV Output Plugin"
        self.plugin_version = "0.0.1"
        self.options = None

    def parseOutputString(self, output, debug=False):

        parser = Ip360Parser(output)
        for host, interface, service, vulnerability in parser.parse():

            h_id = self.createAndAddHost(host.get("name"), host.get("os"))

            i_id = self.createAndAddInterface(
                h_id,
                interface.get("name"),
                ipv4_address=interface.get("name"),
                hostname_resolution=interface.get("hostname_resolution"),
                network_segment=interface.get("network_segment"))


            if service.get("port") == "-":
                port = "0"
                protocol = "unknown"
            else:
                port = service.get("port").split("/")[0]
                protocol = service.get("port").split("/")[1]

            s_id = self.createAndAddServiceToInterface(
                h_id,
                i_id,
                service.get("port"),
                protocol=protocol,
                ports=[port])

            self.createAndAddVulnToService(
                h_id,
                s_id,
                vulnerability.get("name"),
                desc=vulnerability.get("description"),
                resolution=vulnerability.get("resolution"),
                severity=calculate_severity(vulnerability.get("severity")),
                ref=vulnerability.get("ref"))

def createPlugin():
    return Ip360Plugin()