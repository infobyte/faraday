#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Faraday Penetration Test IDE
Copyright (C) 2018 Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from __future__ import with_statement
from plugins import core
from plugins.plugin_utils import get_vulnweb_url_fields
from model import api
import re

try:
    import xml.etree.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def cleanhtml(raw_html):
        cleanr = re.compile('<.*?>')
        cleantext = re.sub(cleanr, '', raw_html)
        return cleantext


class WebInspectParser():

    def __init__(self, output):
        self.xml = ET.fromstring(output)
        self.issues = self.xml.findall("Issues/Issue")

    def parse_severity(self, severity):

        severity_dict = {
            "0": "info",
            "1": "low",
            "2": "med",
            "3": "high",
            "4": "critical"}

        result = severity_dict.get(severity)
        if not result:
            return "info"
        else:
            return result

    def return_text(self, tag,element):
        try:
            text = element.find(tag).text.encode("ascii", errors="backslashreplace")
            return text
        except:
            return ""
    
    def parse(self):

        map_objects_fields = {
            "Name": ["Vuln", "name"],
            "URL": ["Vuln", "website"],
            "Scheme": ["Service", "name"],
            "Host": ["Host", "name"],
            "Port": ["Service", "port"],
            "AttackMethod": ["Vuln", "method"],
            "VulnerableSession": ["Vuln", "request"],
            "VulnerabilityID": ["Vuln", "reference"],
            "RawResponse": ["Vuln", "response"],
            "Summary": ["Vuln", "description"],
            "Implication": ["Vuln", "data"],
            "Fix": ["Vuln", "resolution"],
            "Reference Info": ["Vuln", "reference"],
            "Severity": ["Vuln", "severity"]
        }

        result = []
        for issue in self.issues:

            obj = {
                "Host" : {},
                "Service" : {},
                "Interface" : {},
                "Vuln": {
                    "reference" : []}
            }

            for tag, obj_property in map_objects_fields.iteritems():

                value = self.return_text(tag,issue)

                if value != None:

                    faraday_obj_name = obj_property[0]
                    faraday_field = obj_property[1]
                    if faraday_field == "reference":
                        obj[faraday_obj_name].get("reference").append(value)
                    else:
                        obj[faraday_obj_name].update({faraday_field:value})

            # This for loads Summary, Implication, Fix and Reference
            for section in issue.findall("ReportSection"):

                try:
                    field = section.find("Name").text.encode("ascii", errors="backslashreplace")
                    value = section.find("SectionText").text.encode("ascii", errors="backslashreplace")

                    faraday_obj_name = map_objects_fields.get(field)[0]
                    faraday_field = map_objects_fields.get(field)[1]
                except:
                    continue

                if faraday_field == "reference" and value != "":
                    obj[faraday_obj_name].get("reference").append(cleanhtml(value))
                else:
                    obj[faraday_obj_name].update({faraday_field:value})

            result.append(obj)
        return result


class WebInspectPlugin(core.PluginBase):
    """
    This plugin handles WebInspect reports.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Webinspect"
        self.name = "Webinspect"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"

    def parseOutputString(self, output, debug=False):
        
        parser = WebInspectParser(output)
        vulns = parser.parse()

        for vuln in vulns:

            host_id = self.createAndAddHost(
                vuln.get("Host").get("name"))

            interface_id = self.createAndAddInterface(
                host_id, vuln.get("Host").get("name"))

            service_id = self.createAndAddServiceToInterface(
                host_id, interface_id,
                vuln.get("Service").get("name"),
                protocol=vuln.get("Service").get("name"),
                ports=[vuln.get("Service").get("port")])
            
            self.createAndAddVulnWebToService(
                host_id, service_id,
                vuln.get("Vuln").get("name"),
                website=get_vulnweb_url_fields(vuln.get("Vuln").get("website")).get("website"),
                path=get_vulnweb_url_fields(vuln.get("Vuln").get("website")).get("path"),
                query=get_vulnweb_url_fields(vuln.get("Vuln").get("website")).get("query"),
                method=vuln.get("Vuln").get("method"),
                request=vuln.get("Vuln").get("request"),
                ref=filter(None ,vuln.get("Vuln").get("reference")),
                response=vuln.get("Vuln").get("response"),
                desc=cleanhtml(vuln.get("Vuln").get("description")),
                resolution=cleanhtml(vuln.get("Vuln").get("resolution")),
                severity=parser.parse_severity(vuln.get("Vuln").get("severity"))
            )

        return True

    def processCommandString(self, username, current_path, command_string):
        return None

def createPlugin():
    return WebInspectPlugin()
