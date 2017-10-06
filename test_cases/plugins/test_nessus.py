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
from model.common import factory
from persistence.server.models import (
    Vuln,
    Credential,
    VulnWeb,
    Note,
    Host,
    Service,
)
from plugins.modelactions import modelactions
import test_common


class NessusParserTest(unittest.TestCase):
    cd = os.path.dirname(os.path.realpath(__file__))

    def setUp(self):
        self.plugin = NessusPlugin()
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)

    def test_Plugin_Calls_createAndAddHost(self):
        self.plugin.processReport(self.cd + '/nessus_xml')
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDHOST)
        self.assertEqual(action[1].name, "12.233.108.201")
        # action = self.plugin._pending_actions.get(block=True)
        # self.assertEqual(action[0], modelactions.ADDINTERFACE)
        # self.assertEqual(action[2].name, "12.233.108.201")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDVULNHOST)
        self.assertEqual(action[2].name, "Nessus Scan Information")
        test_common.skip(self, 4)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDSERVICEINT)
        self.assertEqual(action[3].ports, [443])
        self.assertEqual(action[3].name, 'https?')
        self.assertEqual(action[3].protocol, 'tcp')


if __name__ == '__main__':
    unittest.main()
