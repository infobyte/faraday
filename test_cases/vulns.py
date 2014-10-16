#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from unittest import TestCase
import unittest
import sys
sys.path.append('.')
import model.controller as controller
import plugins.core as plcore
from mockito import mock
from model import api
from model.hosts import Host, Interface, Service
from managers.model_managers import WorkspaceManager
from model.common import ModelObjectVuln, ModelObjectVulnWeb
from persistence.orm import WorkspacePersister
import random
from persistence.orm import WorkspacePersister


class VulnerabilityCreationTests(unittest.TestCase):

    def testStandarizeNumericVulnSeverity(self):
        """ Verifies numeric severity transformed into 'info, low, high,
        critical' severity"""

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=0)

        self.assertEquals(vuln.severity, 'info',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=1)

        self.assertEquals(vuln.severity, 'low',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=2)

        self.assertEquals(vuln.severity, 'med',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=3)

        self.assertEquals(vuln.severity, 'high',
                    'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=4)

        self.assertEquals(vuln.severity, 'critical', 
                'Vulnerability severity not transformed correctly')


        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=5)

        self.assertEquals(vuln.severity, 'unclassified', 
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=-1)

        self.assertEquals(vuln.severity, 'unclassified', 
                'Vulnerability severity not transformed correctly')

    def testStandarizeShortnameVulnSeverity(self):
        """ Verifies longname  severity transformed into 'info, low, high,
        critical' severity (informational -> info)"""

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='informational')

        self.assertEquals(vuln.severity, 'info',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='medium')

        self.assertEquals(vuln.severity, 'med',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='highest')

        self.assertEquals(vuln.severity, 'high',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='criticalosiuos')

        self.assertEquals(vuln.severity, 'critical',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='tuvieja')

        self.assertEquals(vuln.severity, 'unclassified',
                'Vulnerability severity not transformed correctly')

    def testStandarizeUpdatedSeverity(self):
        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='informational')

        self.assertEquals(vuln.severity, 'info',
                'Vulnerability severity not transformed correctly')

        vuln.updateAttributes(severity='3')
        self.assertEquals(vuln.severity, 'high',
                'Vulnerability severity not transformed correctly')



if __name__ == '__main__':
    unittest.main()

