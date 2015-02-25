#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
import os
sys.path.append(os.path.abspath(os.getcwd()))

from model.common import ModelObjectVuln


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


class VulnerabiltyEdtionTests(unittest.TestCase):
    def testChangeVulnDescription(self):
        """
        Until we have a single attribute to store the vuln's descrption
        we need to make sure we're always accessing the valid one (_desc)
        """
        vuln = ModelObjectVuln(
            name='VulnTest', desc='TestDescription', severity='info')

        self.assertEquals(vuln._desc, 'TestDescription',
            'Vulnerability desc should be the given during creation')

        vuln.setDescription("new description")

        self.assertEquals(vuln.getDescription(), 'new description',
            'Vulnerability desc wasn\'t updated correctly')

        self.assertEquals(vuln._desc, 'new description',
            'Vulnerability desc wasn\'t updated correctly')

    def testChangeVulnDescriptionUsingUpdateAttributesMethod(self):
        """
        Until we have a single attribute to store the vuln's descrption
        we need to make sure we're always accessing the valid one (_desc)
        """
        vuln = ModelObjectVuln(
            name='VulnTest', desc='TestDescription', severity='info')

        self.assertEquals(vuln._desc, 'TestDescription',
            'Vulnerability desc should be the given during creation')

        vuln.updateAttributes(desc="new description")

        self.assertEquals(vuln.getDescription(), 'new description',
            'Vulnerability desc wasn\'t updated correctly')

        self.assertEquals(vuln._desc, 'new description',
            'Vulnerability desc wasn\'t updated correctly')


if __name__ == '__main__':
    unittest.main()

