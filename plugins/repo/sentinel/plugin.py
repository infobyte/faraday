#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from plugins import core
from config.configuration import getInstanceConfiguration
from urlparse import urlparse
import requests
import xmlrpclib
import json
import uuid
import re

__author__ = "Alejandro Parodi"
__copyright__ = "Copyright (c) 2016, Infobyte LLC"
__credits__ = ["Parodi, Alejandro Julián"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Alejandro Parodi"
__email__ = "aparodi@infobytesec.com"
__status__ = "Development"


class SentinelPlugin(core.PluginBase):
    """
    This plugin get information from Sentinel Tool.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Sentinel"
        self.name = "Sentinel Online Plugin"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        self.baseURL = "https://sentinel.whitehatsec.com/api/"
        self.vulnURL = "https://source.whitehatsec.com/site_vuln_detail.html?site_id="

        self.addSetting("Api_key", str, "")
        self.addSetting("Enable", str, "0")

        self.faraday_config = 'http://' + getInstanceConfiguration().getApiConInfoHost() + ':' + str(getInstanceConfiguration().getApiConInfoPort()) + '/'
        self.faraday_api = xmlrpclib.ServerProxy(self.faraday_config)
        self.format = "?format=json&display_all=1&key="
        self._command_regex = re.compile(
            r'^(sudo sentinel|sentinel).*?')

    def parseOutputString(self, output, debug=False):

        if self.getSetting("Api_key") == "":
            self.log("Please set Sentinel API in plugin configuration", "ERROR")
            return True

        allVulns = self.getAllVulns()
        for element in allVulns['collection']:

            vulnClass = element.get('class', "Vuln_Without_Title")
            severity = element.get('severity', "INFO")
            host = element.get('url', 'Unknown Hostname')

            hostId = self.faraday_api.createAndAddHost(host, "")

            interfaceId = self.faraday_api.createAndAddInterface(
                hostId,
                host,
                '00:00:00:00:00:00',
                '0.0.0.0',
                '0.0.0.0',
                '0.0.0.0',
                [],
                host)

            serviceId = self.faraday_api.createAndAddServiceToInterface(hostId, interfaceId, "HTTP")
            vulnData = self.getAttackVector(element.get('href', 'unknown'))

            for vuln in vulnData['collection']:

                vuln_information  = self.getVulnInformation(element.get('href', 'unknown')) 

                desc = vuln_information.get("description", "").get("description_prepend", "")
                solution = vuln_information.get("solution", "").get("solution_prepend", "")
                siteId = vuln_information.get("site", "Unknown")
                id = vuln_information.get("id", uuid.uuid4())

                vulnUrlComplete = self.vulnURL + siteId + "&vuln_id=" + id
                
                cvss = "CVSS: " + vuln_information.get("cvss_score", "")
                siteName = "Site-Name: " + vuln_information.get("site_name", "Unknown")

                found = vuln.get('found', '0000-00-00T00:00:00Z')
                tested = vuln.get('tested', '0000-00-00T00:00:00Z')
                request = vuln.get('request', {})#{}
                
                state = "State: " + vuln.get('state', 'Unknown')
                

                if(len(request)>0):

                    url = request.get('url', "Unknown")
                    method = request.get('method', "Unknown")
                    headers = request.get("headers", [])
                    reqHeader = ""
            
                    if(headers == None):
                        headers = []
            
                    for parts in headers:
                        reqHeader += parts.get("name", "") + ":" + parts.get("value", "")+"\n"
            
                    body = request.get("body", {})#{}
            
                    if(len(body)>0):
                        bodyContent = body.get('content', "")
            
                response = vuln.get('response', {})#{}
            
                if(len(response)>0):

                    status = str(response.get("status", ""))
                    headers = response.get("headers", [])
                    resHeader = ""

                    if (headers == None):
                        headers = []

                    for parts in headers:
                        resHeader += parts.get("name", "") + ":" + parts.get("value", "") + "\n"

                    resBody = response.get("body", {})#{}
                    if(len(resBody)>0):
                        resBodyMatch = resBody.get("body_match", {})#
                        resBodyContent = resBodyMatch.get("content", "")

                data = "\n\nFound: " + found + "\n" + "Tested: " + tested + "\n" + state
                req = ""
                res = ""

                if(len(request)>0):

                    req = method+" "+url+"\n"
                    req += reqHeader+"\n"
                    req += bodyContent

                if (len(response)>0):

                    res = "Status: "+status+"\n"
                    res += resHeader+"\n"
                    res += resBodyContent

                name = vulnClass+" ID: "+id
                
                self.faraday_api.createAndAddVulnWebToService(hostId,
                                                            serviceId, name,
                                                            desc + data,
                                                            [cvss, state, siteName, vulnUrlComplete],
                                                            severity, solution, url, "", req, res,
                                                            method, "", "", "", "")
        return True

    def getAllVulns(self):
        req = self.baseURL+"vuln"+self.format+self.getSetting("Api_key")
        r = requests.get(req)
        return json.loads(r.text)

    def getAttackVector(self, path):
        if(path != "unknown"):
            req = self.baseURL + path[5:] + "/attack_vector" +self.format + self.getSetting("Api_key")
            r = requests.get(req)
            return json.loads(r.text)
        else:
            return json.loads("{'colection':[]}")

    def getVulnInformation(self, path):
        req = self.baseURL + path[5:] + self.format + self.getSetting("Api_key") + "&display_description=1&display_solution=1&display_cvss=1"
        r = requests.get(req)
        return json.loads(r.text)

    def processCommandString(self, username, current_path, command_string):
        return


def createPlugin():
    return SentinelPlugin()
