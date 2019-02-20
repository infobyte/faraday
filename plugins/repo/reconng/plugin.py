#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''
import re
import json
import logging
try:
	from lxml import etree as ET
except ImportError:
	import xml.etree.ElementTree as ET

from plugins.core import PluginBase

__author__ = 'Leonardo Lazzaro'
__copyright__ = 'Copyright (c) 2017, Infobyte LLC'
__credits__ = ['Leonardo Lazzaro']
__license__ = ''
__version__ = '0.1.0'
__maintainer__ = 'Leonardo Lazzaro'
__email__ = 'leonardol@infobytesec.com'
__status__ = 'Development'

logger = logging.getLogger(__name__)

class ReconngParser(object):

    def __init__(self, output):
        self._format = self.report_format(output)
        self.hosts = []
        self.vulns = []
        self.host_mapper = []

        if self._format == 'xml':
            self.parsable_tree = self.get_parseable_xml_output(output)
            self.parse_xml_report(self.parsable_tree)

        elif self._format == 'json':
            self.parse_json_report(output)


    def report_format(self, output):
        xml_format_regex = re.compile(r'^<(.*?)>')
        json_format_regex = re.compile(r'(^{)')

        if xml_format_regex.match(output):
            output_format = 'xml'
        elif json_format_regex.match(output):
            output_format = 'json'
        else:
            return False

        return output_format

    def get_parseable_xml_output(self, xml_output):
        try:
            tree = ET.fromstring(xml_output)
            return tree
        except IndexError:
            print "Syntax error"
            return None

    def parse_xml_report(self, tree):
        hosts_items = tree.xpath('//hosts/item')
        self.hosts_from_report(hosts_items)

        vulnerabilities_items = tree.xpath('//vulnerabilities/item')
        self.vulns_from_report(vulnerabilities_items)

    def parse_json_report(self, output):
        reconng_data = json.loads(output)
        hosts_items = reconng_data.get('hosts', '')
        self.hosts_from_report(hosts_items)

        vulns_items = reconng_data.get('vulnerabilities','')
        self.vulns_from_report(vulns_items)

    def hosts_from_report(self, hosts_items):
        for host in hosts_items:
            host_info = self.get_info_from_host_element(host)
            self.hosts.append(host_info)

    def vulns_from_report(self, vulns_items):
        for vuln in vulns_items:
            vuln_info = self.get_info_from_vuln_element(vuln)
            self.vulns.append(vuln_info)

    def get_info_from_host_element(self, element):
        info = {}
        if self._format == 'xml':
            info['host'] = element.find('host').text
            info['ip'] = element.find('ip_address').text

        elif self._format == 'json':
            info['host'] = element['host']
            info['ip'] = element['ip_address']

        self.host_mapper.append(info['host'])
        return info

    def get_info_from_vuln_element(self, element):
        info = {}
        if self._format == 'xml':
            info['host'] = element.find('host').text
            info['refs'] = element.find('reference').text
            info['module'] = element.find('module').text
            info['example'] = element.find('example').text
            info['category'] = element.find('category').text
            if 'SSL' in info['category']:
                info['severity'] = 'med'
            else:
                info['severity'] = 'info'

        elif self._format == 'json':
            if 'SSL' in element['category']:
                info['severity'] = 'med'
            else:
                info['severity'] = 'info'
            info['category'] = element['category']
            info['host'] = element['host']
            info['module'] = element['module']
            info['refs'] = element['reference']
            info['example'] = element['example']

        return info

class ReconngPlugin(PluginBase):
    """
    Example plugin to parse qualysguard output.
    """

    def __init__(self):

        PluginBase.__init__(self)
        self.id = 'Reconng'
        self.name = 'Reconng XML Output Plugin'
        self.plugin_version = '0.0.2'
        self.version = ''
        self.framework_version = ''
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(
            r'records added to')

    def parseOutputString(self, output):
        parser = ReconngParser(output)

        for host in parser.hosts:
            h_id = self.createAndAddHost(
                host['ip'],
                hostnames=[host['host']]
            )
        '''self.createAndAddVulnToHost(
            name='Recon-ng found: ' + vulnerability['example'],
            desc='Found by module: ' + vulnerability['module'],
            severity=severity,
            ref=[vulnerability['reference']],
            host_id=hosts_id_mapper[vulnerability['host']]
        )'''

    def processCommandString(self, username, current_path, command_string):
        return

def createPlugin():
    return ReconngPlugin()

if __name__ == '__main__':
    with open("/home/javier/results_hosts_vulns.xml","r") as report:
        parser = ReconngParser(report.read())
        #for item in parser.items:
            #if item.status == 'up':
                #print item
