#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import unittest
import sys
import os
sys.path.append(os.path.abspath(os.getcwd()))
from plugins.repo.nessus.plugin import NessusPlugin
from model.common import (
    factory, ModelObjectVuln, ModelObjectCred,
    ModelObjectVulnWeb, ModelObjectNote
)
from model.hosts import (
    Host, Service, Interface
)
from plugins.modelactions import modelactions
import test_common

class NessusParserTest(unittest.TestCase):
    cd = os.path.dirname(os.path.realpath(__file__))

    def setUp(self):
        self.plugin = NessusPlugin()
        factory.register(Host)
        factory.register(Interface)
        factory.register(Service)
        factory.register(ModelObjectVuln)
        factory.register(ModelObjectVulnWeb)
        factory.register(ModelObjectNote)
        factory.register(ModelObjectCred)

    def test_Plugin_Calls_createAndAddHost(self):
        self.plugin.processReport(self.cd + '/nessus_xml')
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDHOST)
        self.assertEqual(action[1], "12.233.108.201")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDINTERFACE)
        self.assertEqual(action[2], "12.233.108.201")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDVULNHOST)
        self.assertEqual(action[2], "Nessus Scan Information")
        test_common.skip(self, 4)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDSERVICEINT)
        self.assertEqual(action[5], ['443'])
        self.assertEqual(action[3], 'https?')
        self.assertEqual(action[4], 'tcp')

if __name__ == '__main__':
    unittest.main()
