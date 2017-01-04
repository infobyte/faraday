#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from plugins import core
import re
import socket
import json

__author__ = "Joaquin L. Pereyra | Federico Fernandez"
__copyright__ = "Copyright (c) 2016, Infobyte LLC"
__credits__ = ["Joaquin L. Pereyra"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Joaquin L. Pereyra"
__email__ = "joaquinlp@infobytesec.com"
__status__ = "Development"


class WPScanPlugin(core.PluginBase):
    """ Handle the WPScan tool. Detects the output of the tool
    and adds the information to Faraday.
    """

    def __init__(self):
        """Initalizes the plugin with some basic params.
        Right now the plugin doesnt support being executed from another folder,
        like /dir/wpscan.rb
        """
        core.PluginBase.__init__(self)
        self.id = "wpscan"
        self.name = "WPscan"
        self.plugin_version = "0.0.1"
        self.version = "2.9.1"
        self._command_regex = re.compile(
                r"^((sudo )?(ruby )?(\.\/)?(wpscan)(.rb)?)")
        self.addSetting("WPscan path", str, "~/wpscan")
        self.wpPath         = self.getSetting("WPscan path")
        self.themes         = {}
        self.plugins        = {}
        self.wpversion      = ''
        self.risks          = {'AUTHBYPASS' : 'high',
         		       'BYPASS'     : 'med',
         		       'CSRF'       : 'med',
                               'DOS'        : 'med',
                               'FPD'        : 'info',
                               'LFI'        : 'high',
                               'MULTI'      : 'unclassified',
                               'PRIVESC'    : 'high',
                               'RCE'        : 'critical',
                               'REDIRECT'   : 'low',
                               'RFI'        : 'critical',
                               'SQLI'       : 'high',
                               'SSRF'       : 'med',
                               'UNKNOWN'    : 'unclassified',
                               'UPLOAD'     : 'critical',
                               'XSS'        : 'high',
                               'XXE'        : 'high'
                               }

    def getPort(self, host, proto):
        p = re.search(r"\:([0-9]+)\/", host)
        if p is not None:
            return p.group(1)
        elif proto == 'https':
            return 443
        else:
           return 80


    def parseOutputWpscan(self, output):
	sp = output.split('0m Name:') #cut by name
	for e in sp:
    	    if 'Title:' in e:
                if 'WordPress version' in e:
                    r = re.search(r'WordPress version ([\d\.]+) identified', e) #get wordpress version
                    self.wpversion = r.group(1)

                elif 'wp-content/themes/' in e:
                    name  = re.findall(r"Location: .+themes\/(.+)\/", e) # get theme name
                    title = re.findall(r"Title: (.+)", e) # get vulnerabilities title
                    self.themes[name[0]] = title #insert theme in dicc {'themeName' : ['titles', 'titles']}

                else:
                    name = re.findall(r"Location: .+plugins\/(.+)\/", e) #get plugin name
                    title     = re.findall(r"Title: (.+)", e) #get vulnerabilities title
                    self.plugins[name[0]] = title #insert plugin in dicc {'plugin' : ['titles', 'titles']}

    def addThemesOrPluginsVulns(self, db, dic, host_id, serv_id, domain, wp_url, name):
        with open(self.wpPath+'/data/'+db, "r") as data:
            j = json.load(data)
            for p in dic:
                for title in dic[p]:
                    for vuln in j[p]['vulnerabilities']: #iter vulnerabilities
                        if vuln['title'] == title: # if output title is equal
                            title     = vuln['title'] #title
                            risk      = self.risks[vuln['vuln_type']] #vuln type (xss,rce,lfi,etc) - risk
                            location  = wp_url+'wp-content/'+name+'/'+p+'/'
                            if vuln['references'].has_key('url') == True: #if references
                                refs = vuln['references']['url'] #references[]
                            else:
                                refs = [] #references null
                            self.createAndAddVulnWebToService(host_id, serv_id, title, severity = risk, website = domain, ref = refs, path = location)


    def addWPVulns(self, db, version, host_id, serv_id, domain):
        with open(self.wpPath+'/data/'+db, "r") as data:
            j = json.load(data)
            for vuln in j[version]['vulnerabilities']: #iter vulnerabilities
                title     = vuln['title'] #title
                risk      = self.risks[vuln['vuln_type']] #vuln type (xss,rce,lfi,etc) - risk
                if vuln['references'].has_key('url') == True: #if references
                    refs = vuln['references']['url'] #references[]
                else:
                    refs = [] #references null
                self.createAndAddVulnWebToService(host_id, serv_id, title, severity = risk, website = domain, ref = refs)


    def parseOutputString(self, output, debug=False):
        """Parses the output given as a string by the wpscan tool and creates
        the appropiate hosts, interface, service and vulnerabilites. Return
        nothing.
        """
        self.parseOutputWpscan(output)
        wp_url  = re.search(r"URL: ((http[s]?)\:\/\/([\w\.]+)[.\S]+)", output)
        service, base_url = self.__get_service_and_url_from_output(output)
        port = self.getPort(wp_url.group(1), service)
        host_ip = socket.gethostbyname_ex(base_url)[2][0]
        host_id = self.createAndAddHost(host_ip)
        interface_id = self.createAndAddInterface(host_id, host_ip,
                                                  ipv4_address=host_ip,
                                                  hostname_resolution=base_url)

        service_id = self.createAndAddServiceToInterface(host_id, interface_id,
                                                         service, "tcp", ports = [port])

        potential_vulns = re.findall(r"(\[\!\].*)", output)
        for potential_vuln in potential_vulns:
            vuln_name, severity = self.__get_name_and_severity(potential_vuln)
            if vuln_name is not None:
                vuln = potential_vuln  # they grow up so fast
                path = self.__get_path_from_vuln(vuln)
                self.createAndAddVulnWebToService(host_id, service_id,
                                                  name=vuln_name,
                                                  website=base_url,
                                                  path=path, severity=severity)
        
        if len(self.plugins) > 0:
            self.addThemesOrPluginsVulns('plugins.json', self.plugins, host_id, service_id, base_url, wp_url.group(1), 'plugins')
        if len(self.wpversion) > 0:
            self.addWPVulns('wordpresses.json', self.wpversion, host_id, service_id, base_url)
        if len(self.themes) > 0:
            self.addThemesOrPluginsVulns('themes.json', self.themes, host_id, service_id, base_url, wp_url.group(1), 'themes')

    
    def __get_service_and_url_from_output(self, output):
        """ Return the service (http or https) and the base URL (URL without
        protocol) from a given string. In case more than one URL is found,
        return the service and base_url of the first one, ignore others.
        """
        search_url = re.search(r"\[\+\](.*?)URL: (https?)://(.*?)/", output)
        service, base_url = search_url.group(2), search_url.group(3)
        return service, base_url

    def __get_name_and_severity(self, potential_vuln):
        """Regex the potential_vuln string against a regex with all
        the vulnerabilities given by WPscan. Returns a regex match object with
        the vulnerability's name and severity if the regex found something
        and (None, None) if the regex found nothing.
        """
        critical_search = re.search(r"Website is not fully configured|"
                                    "Debug log file found|"
                                    "wp-config\.php backup file has been found|"
                                    "searchreplacedb2.php has been found",
                                    potential_vuln)
        if critical_search:
            return critical_search.group(0), "critical"

        info_search = re.search(r"Directory listing is enabled|"
                                "An error_log file has been found|"
                                "file exists exposing a version number|"
                                "Full Path Disclosure|"
                                "Registration is enabled|"
                                "(Upload|Includes) directory has directory listing enabled|"
                                "Default first Wordpress username 'admin' is still used",
                                potential_vuln)
        if info_search:
            return info_search.group(0), "info"

        return None, None

    def __get_path_from_vuln(self, vuln):
        """Given a vuln as string, return the path as a string (empty string
        for path not found).
        """
        path_search = re.search("(?P<url>https?://[^\s]+)", vuln)
        path = path_search.group('url') if path_search else ""
        return path

    def processCommandString(self, username, current_path, command_string):
        return None


def createPlugin():
    return WPScanPlugin()
