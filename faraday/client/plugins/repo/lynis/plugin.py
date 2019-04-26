#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from __future__ import with_statement
import re
import os
import random
import socket
from collections import defaultdict

from faraday.client.plugins import core
from faraday.client.plugins.plugins_utils import filter_services, get_all_protocols


current_path = os.path.abspath(os.getcwd())


class LynisLogDataExtracter():
    def __init__(self, datfile=None, output=None):
        self.services = defaultdict(list)
        if datfile and os.path.exists(datfile):
            with open(datfile) as f:
                self.rawcontents = f.read()

        if output:
            self.rawcontents = output

    def _svcHelper(self, ip, port, protocol, name):
        self.services[ip].append({'port': port, 'protocol': protocol, 'name': name})

    def hostname(self):
        hostname_match = re.search('^hostname=(.+)$', self.rawcontents, re.MULTILINE)
        hostname = hostname_match.group(1).strip()
        domain_match = re.search('^domainname=(.+)$', self.rawcontents, re.MULTILINE)
        if domain_match:
            domain = domain_match.group(1).strip()
            return ".".join([hostname,domain])
        else:
            return hostname

    def osfullname(self):
        name_match = re.search('^os_name=(.+)$', self.rawcontents, re.MULTILINE)
        name = name_match.group(1).strip()
        version_match = re.search('^os_version=(.+)$', self.rawcontents, re.MULTILINE)
        version = version_match.group(1).strip()
        return " ".join([name, version])

    def ipv4(self):
        ipv4addrs = []
        ipv4s = re.findall('^network_ipv4_address\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        ipv4addrs = self.ipv4_filter(ipv4s)
        return(ipv4addrs)

    def ipv6(self):
        ipv6addrs = []
        ipv6s = re.findall('^network_ipv6_address\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        ipv6addrs = self.ipv6_filter(ipv6s)
        return(ipv6addrs)

    def ipv4_filter(self, ips):
        ip_list = []
        for ip in ips:
            if not ip == "127.0.0.1":
                ip_list.append(ip)

        return ip_list

    def ipv6_filter(self, ips):
        ip_list = []
        for ip in ips:
            if not ip.startswith('fe80') and not ip.startswith('::1'):
                ip_list.append(ip)

        return ip_list

    def kernelVersion(self):
        versions_dict = {}

        version = re.search('^os_kernel_version=(.+)$',
                      self.rawcontents, re.MULTILINE)
        if version:
            versions_dict['Kernel Version'] = version.group(1).strip()

        version_full = re.search('^os_kernel_version_full=(.+)$',
                      self.rawcontents, re.MULTILINE)
        if version_full:
            versions_dict['Kernel Version Full'] = version_full.group(1).strip()

        return versions_dict

    def listeningservices(self):
        line = re.findall('^network_listen_port\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        # To avoid local services, we will create the following list
        local_services = ['*', 'localhost']

        for combo in line:
            elements = self.clean_services(combo, local_services)
            if elements is not None:
                self._svcHelper(elements['ip'],
                                elements['port'],
                                elements['protocol'],
                                elements['name'])
        return self.services

    def clean_services(self, combo, local_services):
        add = False
        #if "localhost" in combo:
        if combo.count("|") > 1:
            # Service with url, protocol and perhaps name
            items_service = combo.split('|')
            if not self.local_service(items_service, local_services):
                # self.aux_items will be an auxiliar list. We will use it...
                # ...for poping the url and the protocol so that the last element...
                # ... of the list, will be the name of the service
                self.aux_items = filter(None, items_service)
                elements_ip_port, count = self.get_ip_and_port(self.aux_items, remove_from_list=True)
                protocol = self.get_protocol()
                name = self.aux_items[0]
                add = True

                if name == '-':
                    details = self.search_service(elements_ip_port[1])
                    name = details['name']
        elif combo.count('|') == 1:
            # Service only with url
            items_service = combo.split('|')
            if not self.local_service(items_service, local_services):
                elements_ip_port, count = self.get_ip_and_port(items_service)
                details = self.search_service(elements_ip_port[1])
                protocol = details['protocol']
                name = details['name']
                add = True
        else:
            items_service = combo
            count = items_service.count(':')
            elements_ip_port = items_service.split(':')
            details = self.search_service(elements_ip_port[1])
            protocol = details['protocol']
            name = details['name']
            add = True

        if add:
            ip, port = self.colon_count(count, elements_ip_port, items_service)
            elements_dict = {
                "ip":ip,
                "port": port,
                "protocol": protocol,
                "name": name
            }
            return elements_dict
        else:
            return None

    def local_service(self, service_data, local_services):
        ip = self.get_ip_and_port(service_data)[0][0]
        local = True
        if not ip in local_services and not ip.startswith(':'):
            local = False

        return local

    def get_ip_and_port(self, service_data, remove_from_list=False):
        url_data = [url for url in service_data if ':' in url][0]
        count = url_data.count(':')
        ip_port = url_data.split(':')

        if remove_from_list:
            self.aux_items.remove(url_data)

        return ip_port, count

    def get_protocol(self):
        # network_listen_port variables are different in .log and .dat reports
        # .log: tcp4|127.0.0.1:5985|zabbix_age|
        # .dat: 127.0.0.1:5985|tcp4|zabbix_age|
        # This method will check if the protocol (from the function get_all_protocols())
        # matches with the protocol that network_listen_port contains
        protocols = get_all_protocols()
        for item in protocols:
            protocol = [p for p in self.aux_items if item in p.lower()]
            if protocol:
                self.aux_items.remove(protocol[0])
                return protocol[0]

    def search_service(self, port):
        srv = filter_services()
        details_dict = {
            'name' : 'Unknown',
            'protocol' : 'Unknown'
        }
        for item in srv:
            service_tuple = item[0].split('/')
            parsed_port = service_tuple[0]
            if parsed_port == port:
                details_dict['name'] = item[1]
                details_dict['protocol'] = service_tuple[1]
                return details_dict
        return details_dict

    def colon_count(self, count, elements_ip_port, items_service):
        #Ipv4
        if count == 1:
            ip, port = elements_ip_port

        #Ipv6
        elif count == 3:
            port = elements_ip_port[3]
            ip = '::'

        #Ipv6
        elif count == 5:
            port = elements_ip_port[5]
            ip = items_service[0].replace(':{}'.format(port), '')

        return ip, port

    def parse_suggestions(self):
        sugs = {}
        m = re.findall('^suggestion\[\]=(.+)$', self.rawcontents, re.MULTILINE)
        for combo in m:
            x = combo.split('|')
            sugs[x[0]] = x[1]
        return(sugs)

    def parse_warnings(self):
        warns = {}
        m = re.findall('^warning\[\]=(.+)$', self.rawcontents, re.MULTILINE)
        for combo in m:
            x = combo.split('|')
            warns[x[0]] = x[1]
        return(warns)


class LynisPlugin(core.PluginBase):
    """ Simple example plugin to parse lynis' lynis-report.dat file."""

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Lynis"
        self.name = "Lynis DAT Output Plugin"
        self.plugin_version = "0.4"
        self.version = "2.7.1"
        self.options = None
        self._current_output = None
        rr = r'^(lynis|sudo lynis|\.\/lynis|sudo \.\/lynis).*?'
        self._command_regex = re.compile(rr)
        self._hosts = []

        global current_path

    def parseOutputString(self, output, debug=False):
        datpath = self.getDatPath(output)

        if datpath:
            lde = LynisLogDataExtracter(datfile=datpath)
        elif '# Lynis Report' in output:
            lde = LynisLogDataExtracter(output=output)
        hostname = lde.hostname()
        ipv4s = lde.ipv4()
        ipv6s = lde.ipv6()
        kernel_versions = lde.kernelVersion()
        services = lde.listeningservices()
        suggestions = lde.parse_suggestions()
        warnings = lde.parse_warnings()

        for ipv4 in ipv4s:
            h_id = self.createAndAddHost(name=ipv4,
                                            os=lde.osfullname(),
                                            hostnames=[hostname])

            self.create_services(h_id, services, ipv4)
            self.create_vulns_with_kernel(h_id, kernel_versions)
            self.create_vulns_with_suggestions(h_id, suggestions)
            self.create_vulns_with_warns(h_id, warnings)

        for ipv6 in ipv6s:
            h_id = self.createAndAddHost(name=ipv6,
                                            os=lde.osfullname(),
                                            hostnames=[hostname])

            self.create_services(h_id, services, ipv6)
            self.create_vulns_with_kernel(h_id, kernel_versions)
            self.create_vulns_with_suggestions(h_id, suggestions)
            self.create_vulns_with_warns(h_id, warnings)

    def create_services(self, host_id, parsed_services, ip_version):
        for service_data in parsed_services[ip_version]:
            self.createAndAddServiceToHost(host_id=host_id,
                                            name=service_data['name'],
                                            protocol=service_data['protocol'],
                                            ports=[service_data['port']])

        if '0.0.0.0' in parsed_services:
            for service_data in parsed_services['0.0.0.0']:
                self.createAndAddServiceToHost(host_id=host_id,
                                            name=service_data['name'],
                                            protocol=service_data['protocol'],
                                            ports=[service_data['port']])

    def create_vulns_with_kernel(self, host_id, kernel_versions):
        for kernel, version in kernel_versions.iteritems():
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=kernel,
                severity='info',
                desc=version
            )

    def create_vulns_with_suggestions(self, host_id, sugs):
        for sug in sugs:
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=sug,
                severity='med',
                desc=sugs[sug]
            )

    def create_vulns_with_warns(self, host_id, warns):
        for warn in warns:
            self.createAndAddVulnToHost(
                host_id=host_id,
                name=warn,
                severity='high',
                desc=warns[warn]
            )

    def processCommandString(self, username, current_path, command_string):
        """
        Lynis does not have a means to specify the location for the
        DAT file, which by default goes to /var/log/lynis-report.dat
        or /tmp/lynis-report.dat, depending on privileges.
        Because of that, we will extract the DAT location off
        lynis' output via parseOutputString().
        """
        return

    def getDatPath(self, output):
        m = re.search('(\/.+\.dat)$', output, re.MULTILINE)
        if m:
            return(m.group(0).strip())


def createPlugin():
    return LynisPlugin()
