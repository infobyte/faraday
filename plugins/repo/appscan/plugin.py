#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import pprint
import socket
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
    except Exception as e:
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

    def parse_issue_type(self):
        res = {}

        for issue_type in self.obj_xml["issue-type-group"]["item"]:
            res[issue_type.attrib['id']] = {
                'name': issue_type.name.text, 
                'advisory': issue_type["advisory"]["ref"].text,
                'fix-recommendation': issue_type["fix-recommendation"]["ref"].text
                } 

            if "cve" in issue_type:
                res[issue_type.attrib['id']] = {'cve': issue_type["cve"].text} 
        
        return res

    
    def parse_advisory_group(self, advisory):
        '''
        Function that parse advisory-group in order to get the item's description
        '''
        for item in self.obj_xml["advisory-group"]["item"]:
            if item.attrib['id'] == advisory:
                return item['advisory']['testTechnicalDescription']['text'].text


    def get_url(self, ref):
        for item in self.obj_xml['url-group']['item']:
            if item.attrib['id'] == ref:
                return item['name'].text


    def parse_issues(self):
        issue_type = self.parse_issue_type()
        for issue in self.obj_xml["issue-group"]["item"]:
            issue_data = issue_type[issue['issue-type']['ref']]
            obj_issue = {}

            obj_issue["name"] = issue_data["name"]
            obj_issue['advisory'] = issue_data["advisory"]

            if("cve" in issue_data):
                obj_issue['cve'] = issue_data["cve"].text

            obj_issue['url'] = self.get_url(issue['url']['ref'].text)
            obj_issue['cvss_score'] = issue["cvss-score"].text
            obj_issue['response'] = issue['variant-group']['item']['issue-information']["testResponseChunk"].text
            obj_issue['request'] = issue['variant-group']['item']["test-http-traffic"].text
            obj_issue['severity'] = issue['severity'].text
            obj_issue['issue-description'] = self.parse_advisory_group(issue_data['advisory'])

            for recomendation in self.obj_xml["fix-recommendation-group"]["item"]:
                full_data = ""
                if(recomendation.attrib['id'] == issue_data["fix-recommendation"]):
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
            url_parsed = urlparse(str(issue['url']))

            host_id = self.createAndAddHost(url_parsed.hostname)

            service_id = self.createAndAddServiceToHost(
                host_id,
                url_parsed.scheme,
                ports=[url_parsed.port],
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
                website=url_parsed.netloc,
                path=url_parsed.path,
                request=cleaner_unicode(issue["request"]) if "request" in issue else "",
                response=cleaner_unicode(issue["response"]) if "response" in issue else "",
                method=issue["request"][0:3] if "request" in issue else "")

        return

    def processCommandString(self, username, current_path, command_string):
        return


def createPlugin():
    return AppscanPlugin()


if __name__ == '__main__':
    parser = AppscanPlugin()
    with open('/home/javier/Reports_Testing/MCMD.XML', 'r') as report:
        parser.parseOutputString(report.read())
        for item in parser.items:
            if item.status == 'up':
                print item