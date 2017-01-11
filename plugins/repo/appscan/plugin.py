#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import pprint
from plugins import core
from lxml import objectify
from urlparse import urlparse

__author__ = "Alejando Parodi, Ezequiel Tavella"
__copyright__ = "Copyright (c) 2015, Infobyte LLC"
__credits__ = ["Alejando Parodi", "Ezequiel Tavella"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Ezequiel Tavella"
__status__ = "Development"


def get_ip(domain):
    try:
        data = socket.gethostbyname_ex(domain)
        ip = repr(data[2])
        return ip
    except Exception:
        return domain


def cleaner_unicode(string):
    if string is not None:
        return string.encode('ascii', errors='backslashreplace')
    else:
        return string


class AppscanParser():

    def __init__(self, output):
        self.issue_list = []
        self.obj_xml = objectify.fromstring(output)

    def parse_issues(self):

        for issue in self.obj_xml["issue-type-group"]["item"]:
            url_list = []
            obj_issue = {}

            obj_issue["name"] = issue["name"].text
            obj_issue['advisory'] = issue["advisory"]["ref"].text

            if(issue["cve"]):
                obj_issue['cve'] = issue["cve"].text

            for threat in self.obj_xml["url-group"]["item"]:
                if threat["issue-type"] == issue["fix-recommendation"]["ref"]:
                    if 'entity-type' in threat:

                        if threat["entity-type"] == "Parameter":
                            url_list.append(
                                {"url": threat['url-name'].text, "vuln_parameter": threat["name"].text})

                        if threat["entity-type"] == "Page":
                            url_list.append(
                                {"url": threat['url-name'].text, "vuln_parameter": ""})

                    else:
                        url_list.append(
                            {"url": threat['name'].text, "vuln_parameter": ""})

                    obj_issue['urls'] = url_list

                    for item in self.obj_xml["issue-group"]["item"]:

                        if int(item["url"]["ref"]) == int(threat.get('id')):
                            if item["issue-type"]["ref"] == threat['issue-type']:

                                http_traffic = item["variant-group"]["item"]["test-http-traffic"].text.split("\n\n")

                                obj_issue["request"] = http_traffic[0]
                                obj_issue["response"] = http_traffic[1]

                        if(issue["threat-class"]["ref"] == item["threat-class"]["ref"]):

                            obj_issue["severity"] = item["severity"].text
                            obj_issue["cvss_score"] = item["cvss-score"].text
                            obj_issue["issue_description"] = item["variant-group"]["item"]["issue-information"]["issue-tip"].text
                            break

            for recomendation in self.obj_xml["fix-recommendation-group"]["item"]:
                full_data = ""
                if(recomendation.attrib['id'] == issue["fix-recommendation"]["ref"]):
                    for data in recomendation['general']['fixRecommendation']["text"]:
                        full_data += '' + data
                    obj_issue["recomendation"] = full_data
                    if(hasattr(recomendation['general']['fixRecommendation'], 'link')):
                        obj_issue["ref_link"] = recomendation['general']['fixRecommendation']['link'].text

            self.issue_list.append(obj_issue)

        return self.issue_list

    def get_scan_information(self):

        scan_information = "File: " + self.obj_xml["scan-information"]["scan-file-name"]\
            + "\nStart: " + self.obj_xml["scan-information"]["scan-date-and-time"]\
            + "\nSoftware: " + self.obj_xml["scan-information"]["product-name"]\
            + "\nVersion: " + self.obj_xml["scan-information"]["product-version"]\
            + "\nScanner Elapsed time: " + self.obj_xml["scan-summary"]["scan-Duration"]

        return scan_information


class AppscanPlugin(core.PluginBase):
    """ Example plugin to parse Appscan XML report"""

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Appscan"
        self.name = "Appscan XML Plugin"
        self.plugin_version = "0.0.1"
        self.options = None

    def parseOutputString(self, output, debug=False):

        parser = AppscanParser(output)
        issues = parser.parse_issues()
        for issue in issues:

            if "urls" not in issue:
                continue

            for url in issue["urls"]:

                url_parsed = urlparse(url["url"])

                # Get domain of URL.
                if url_parsed.netloc:
                    hostname = url_parsed.netloc
                    ip = get_ip(url_parsed.netloc)
                elif url_parsed.path:
                    hostname = url_parsed.path
                    ip = get_ip(url_parsed.path)

                host_id = self.createAndAddHost(ip)
                interface_id = self.createAndAddInterface(
                    host_id,
                    ip,
                    ipv4_address=ip,
                    hostname_resolution=[hostname])

                service_id = self.createAndAddServiceToInterface(
                    host_id,
                    interface_id,
                    "HTTP Server",
                    protocol="tcp?HTTP")

                refs = []
                if "ref_link" in issue:
                    refs.append("Fix link: " + issue["ref_link"])
                if "cvss_score" in issue:
                    refs.append("CVSS Score: " + issue["cvss_score"])
                if "cve" in issue:
                    refs.append("CVE: " + issue["cve"])
                if "advisory" in issue:
                    refs.append("Advisory: " + issue["advisory"])

                self.createAndAddVulnWebToService(
                    host_id,
                    service_id,
                    cleaner_unicode(issue["name"]),
                    cleaner_unicode(issue["issue_description"]) if "issue_description" in issue else "",
                    ref=refs,
                    severity=issue["severity"],
                    resolution=cleaner_unicode(issue["recomendation"]),
                    website=hostname,
                    path=url_parsed.path,
                    request=cleaner_unicode(issue["request"]) if "request" in issue else "",
                    response=cleaner_unicode(issue["response"]) if "response" in issue else "",
                    method=issue["request"][0:3] if "request" in issue else "",
                    pname=url["vuln_parameter"] if url["vuln_parameter"] != "" else "",
                    params=url["vuln_parameter"] if url["vuln_parameter"] != "" else "")

        return

    def processCommandString(self, username, current_path, command_string):
        return


def createPlugin():
    return AppscanPlugin()
