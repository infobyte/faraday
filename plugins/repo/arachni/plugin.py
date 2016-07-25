#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from __future__ import with_statement
from plugins import core
from model import api
import socket
import re

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

__author__ = 'Ezequiel Tavella'
__copyright__ = 'Copyright 2016, Faraday Project'
__credits__ = ['Ezequiel Tavella', 'Matías Ariel Ré Medina', ]
__license__ = ''
__version__ = '1.0.1'
__status__ = 'Development'


class ArachniXmlParser():

    def __init__(self, xml_output):

        self.tree = self.parse_xml(xml_output)

        if self.tree:
            self.issues = self.getIssues(self.tree)
            self.plugins = self.getPlugins(self.tree)
            self.system = self.getSystem(self.tree)

        else:
            self.system = None
            self.issues = None
            self.plugins = None

    def parse_xml(self, xml_output):

        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError, err:
            print 'SyntaxError In xml: %s. %s' % (err, xml_output)
            return None

        return tree

    def getIssues(self, tree):

        # Get vulnerabilities.
        issues_tree = tree.find('issues')
        for self.issue_node in issues_tree:
            yield Issue(self.issue_node)

    def getPlugins(self, tree):

        # Get info about plugins executed in scan.
        plugins_tree = tree.find('plugins')
        return Plugins(plugins_tree)

    def getSystem(self, tree):

        # Get options of scan.
        return System(tree)


class Issue():

    def __init__(self, issue_node):

        self.node = issue_node

        self.name = self.getDesc('name')
        self.severity = self.getDesc('severity')
        self.cwe = self.getDesc('cwe')

        self.remedy_guidance = self.getDesc('remedy_guidance')
        self.description = self.getDesc('description')

        self.var = self.getChildTag('vector', 'affected_input_name')
        self.url = self.getChildTag('vector', 'url')
        self.method = self.getChildTag('vector', 'method')

        self.references = self.getReferences()
        self.parameters = self.getParameters()

        self.request = self.getRequest()
        self.response = self.getResponse()

    def getDesc(self, tag):

        # Get value of tag xml
        description = self.node.find(tag)

        if description != None and description.text != None:
            return description.text.encode('ascii', 'ignore')
        else:
            return 'None'

    def getChildTag(self, main_tag, child_tag):

        # Get value of tag child xml
        main_entity = self.node.find(main_tag)

        if not main_entity:
            return 'None'

        result = main_entity.find(child_tag)

        if result != None and result.text != None:
            return result.text.encode('ascii', 'ignore')
        else:
            return 'None'

    def getReferences(self):
        """
        Returns current issue references on this format
        {'url': 'http://www.site.com', 'name': 'WebSite'}.
        """

        result = []

        references = self.node.find('references')

        if not references:
            return result

        for tag in references.findall('reference'):
            url = tag.get('url')
            result.append(url)

        return result

    def getParameters(self):

        # Get parameters of query
        result = []

        parameters = self.node.find('vector').find('inputs')

        if not parameters:
            return result

        for param in parameters.findall('input'):
            name = param.get('name')
            result.append(name)

        return ' - '.join(result)

    def getRequest(self):

        # Get data about request.
        try:

            raw_data = self.node.find('page').find('request').find('raw')
            data = raw_data.text.encode('ascii', 'ignore')
            return data

        except:
            return 'None'

    def getResponse(self):

        # Get data about response.
        try:

            raw_data = self.node.find('page').find(
                'response').find('raw_headers')
            data = raw_data.text.encode('ascii', 'ignore')
            return data

        except:
            return 'None'


class System():

    def __init__(self, node):

        self.node = node

        self.user_agent = 'None'
        self.url = 'None'
        self.audited_elements = 'None'
        self.modules = 'None'
        self.cookies = 'None'

        self.getOptions()

        self.version = self.getDesc('version')
        self.start_time = self.getDesc('start_datetime')
        self.finish_time = self.getDesc('finish_datetime')

        self.note = self.getNote()

    def getOptions(self):

        # Get values of options scan
        options_string = self.node.find('options').text

        if not options_string:
            return

        regex_modules = re.compile('checks:\n([\w\d\s\W\D\S]{0,})(platforms:)')
        regex_user_agent = re.compile('user_agent:(.+)')
        regex_cookies = re.compile('cookies: {()}')
        regex_url = re.compile('url:(.+)')

        regex_audited_elements = re.compile(
            'audit:\n([\w\d\s\W\D\S]{0,})input:|session:'
        )

        result = re.search(regex_modules, options_string)
        if result.group(1):
            self.modules = result.group(1)

        result = re.search(regex_user_agent, options_string)
        if result.group(1):
            self.user_agent = result.group(1)

        result = re.search(regex_cookies, options_string)
        if result.group(1):
            self.cookies = result.group(1)

        result = re.search(regex_url, options_string)
        if result.group(1):
            self.url = result.group(1)

        result = re.search(regex_audited_elements, options_string)
        if result.group(1):
            self.audited_elements = result.group(1)

    def getDesc(self, tag):

        # Return value of tag
        description = self.node.find(tag)

        if description != None and description.text != None:
            return description.text
        else:
            return 'None'

    def getNote(self):

        # Create string with scan information.
        result = (
            'Scan url:\n' +
            self.url +
            '\nUser Agent:\n' +
            self.user_agent +
            '\nVersion Arachni:\n' +
            self.version +
            '\nStart time:\n' +
            self.start_time +
            '\nFinish time:\n' +
            self.finish_time +
            '\nAudited Elements:\n' +
            self.audited_elements +
            '\nModules:\n' +
            self.modules +
            '\nCookies:\n' +
            self.cookies
        )

        return result


class Plugins():

    """
    Support:
    WAF (Web Application Firewall) Detector (waf_detector)
    Healthmap (healthmap)
    """

    def __init__(self, plugins_node):

        self.plugins_node = plugins_node

        self.healthmap = self.getHealthmap()
        self.waf = self.getWaf()

    def getHealthmap(self):

        # Get info about healthmap
        healthmap_tree = self.plugins_node.find('healthmap')

        # Create urls list.
        list_urls = []
        map_results = healthmap_tree.find('results').find('map')

        for url in map_results:

            if url.tag == 'with_issues':
                list_urls.append('With Issues: ' + url.text)
            else:
                list_urls.append('Without Issues: ' + url.text)

        try:

            result = (
                'Plugin Name: ' +
                healthmap_tree.find('name').text +
                '\nDescription: ' +
                healthmap_tree.find('description').text +
                '\nStatistics:' +
                '\nTotal: ' +
                healthmap_tree.find('results').find('total').text +
                '\nWith Issues: ' +
                healthmap_tree.find('results').find('with_issues').text +
                '\nWithout Issues: ' +
                healthmap_tree.find('results').find('without_issues').text +
                '\nIssues percentage: ' +
                healthmap_tree.find('results').find('issue_percentage').text +
                '\nResults Map:\n' +
                '\n'.join(list_urls)
            )

            return result

        except:
            return 'None'

    def getWaf(self):

        # Get info about waf plugin.
        waf_tree = self.plugins_node.find('waf_detector')

        try:

            result = (
                'Plugin Name: ' +
                waf_tree.find('name').text +
                '\nDescription: ' +
                waf_tree.find('description').text +
                '\nResults:' +
                '\nMessage: ' +
                waf_tree.find('results').find('message').text +
                '\nStatus: ' +
                waf_tree.find('results').find('status').text
            )

            return result

        except:
            return 'None'


class ArachniPlugin(core.PluginBase):

    # Plugin that parses Arachni's XML report files.

    def __init__(self):

        core.PluginBase.__init__(self)
        self.id = 'Arachni'
        self.name = 'Arachni XML Output Plugin'
        self.plugin_version = '1.0.1'
        self.version = '1.3.2'
        self.framework_version = '1.0.0'
        self.options = None

        self._command_regex = re.compile(
            r'^(arachni |\.\/arachni).*?'
        )

        self.protocol = None
        self.hostname = None
        self.port = '80'

        self.address = None

    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.
        """

        parser = ArachniXmlParser(output)

        # Check xml parsed ok...
        if not parser.system:
            print 'Error in xml report... Exiting...'
            return

        self.hostname = self.getHostname(parser.system.url)
        self.address = self.getAddress(self.hostname)

        # Create host and interface
        host_id = self.createAndAddHost(self.address)

        interface_id = self.createAndAddInterface(
            host_id,
            self.address,
            ipv4_address=self.address,
            hostname_resolution=self.hostname
        )

        # Create service
        service_id = self.createAndAddServiceToInterface(
            host_id,
            interface_id,
            self.protocol,
            'tcp',
            ports=[self.port],
            status='Open',
            version='',
            description=''
        )

        # Scan Note.
        noteScan_id = self.createAndAddNoteToService(
            host_id,
            service_id,
            'Scan Information',
            parser.system.note
        )

        # Plugins Notes
        note_id = self.createAndAddNoteToService(
            host_id,
            service_id,
            'Plugins arachni',
            'Plugins used by arachni and results of this.'
        )

        if parser.plugins.waf != 'None':

            note2_id = self.createAndAddNoteToNote(
                host_id,
                service_id,
                note_id,
                'Waf Plugin',
                parser.plugins.waf
            )

        if parser.plugins.healthmap != 'None':

            note3_id = self.createAndAddNoteToNote(
                host_id,
                service_id,
                note_id,
                'Healthmap Plugin',
                parser.plugins.healthmap
            )

        # Create issues.
        for issue in parser.issues:

            description = (
                'Description:\n' +
                issue.description +
                '\n\nSolution:\n' +
                issue.remedy_guidance
            )

            references = issue.references
            if issue.cwe != 'None':
                references.append('CWE-' + issue.cwe)

            issue_id = self.createAndAddVulnWebToService(
                host_id,
                service_id,
                name=issue.name,
                desc=description,
                ref=references,
                severity=issue.severity,
                website=self.hostname,
                path=issue.url,
                method=issue.method,
                pname=issue.var,
                params=issue.parameters,
                request=issue.request,
                response=issue.response
            )

        return

    def processCommandString(self, username, current_path, command_string):

        return

    def getHostname(self, url):

        # Strips protocol and gets hostname from URL.
        reg = re.search(
            '(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*('
            '(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5'
            ']|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0'
            '-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0'
            '-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+'
            '\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pr'
            'o|aero|coop|museum|[a-zA-Z]{2}))[\:]*([0-9]+)*([/]*($|[a-zA-Z0-9\.\,\?'
            '\'\\\+&amp;%\$#\=~_\-]+)).*?$',
            url
        )

        self.protocol = reg.group(1)
        self.hostname = reg.group(4)

        if self.protocol == 'https':
            self.port = 443
        if reg.group(11) is not None:
            self.port = reg.group(11)

        return self.hostname

    def getAddress(self, hostname):

        # Returns remote IP address from hostname.
        try:
            return socket.gethostbyname(hostname)
        except socket.error, msg:
            return self.hostname


def createPlugin():
    return ArachniPlugin()
