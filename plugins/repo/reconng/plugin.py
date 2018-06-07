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
        self.importing_report = True

    def load_from_report(self, output):
        # TODO: add credentials and ports
        reconng_data = json.loads(output)
        hosts_id_mapper = {}
        for host in reconng_data.get('hosts', []):
            h_id = self.createAndAddHost(
                host['ip_address'] or host['host']
            )
            hosts_id_mapper[host['host']] = h_id

        severity_mapper = {
            'Information Disclosure': 'informational'
        }
        for vulnerability in reconng_data.get('vulnerabilities', []):
            if vulnerability['host'] not in hosts_id_mapper:
                logger.warn('Could not find host_id, skipping vulnerability')
                continue
            severity = 'info'
            if 'SSL' in vulnerability['category']:
                severity = 'med'
            self.createAndAddVulnToHost(
                name='Recon-ng found: ' + vulnerability['example'],
                desc='Found by module: ' + vulnerability['module'],
                severity=severity,
                ref=[vulnerability['reference']],
                host_id=hosts_id_mapper[vulnerability['host']]
            )

    def load_from_shell(self, output):
        pass

    def parseOutputString(self, output):
        if self.importing_report:
            self.load_from_report(output)
        else:
            self.load_from_shell(output)

    def parseCommandString(self, username, current_path, command_string):
        self.importing_report = False

def createPlugin():
    return ReconngPlugin()