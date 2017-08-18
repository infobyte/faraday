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
from plugins.repo.burp.plugin import BurpPlugin
from model.common import factory
from persistence.server.models import (
    Vuln,
    VulnWeb,
    Credential,
    Note,
    Host,
    Service,
    Interface
)
from plugins.modelactions import modelactions
import test_common


class BurpTest(unittest.TestCase):

    cd = os.path.dirname(os.path.realpath(__file__))

    def setUp(self):
        self.plugin = BurpPlugin()
        factory.register(Host)
        factory.register(Interface)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)

    def test_Plugin_creates_adecuate_objects(self):
        self.plugin.processReport(self.cd + '/burp_xml')
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDHOST)
        self.assertEqual(action[1].name, "200.20.20.201")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDINTERFACE)
        self.assertEqual(action[2].name, "200.20.20.201")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDSERVICEINT)
        self.assertEqual(action[3].name, 'http')
        self.assertEqual(action[3].protocol, 'tcp')
        self.assertEqual(action[3].ports, [80])
        self.assertEqual(action[3].status, 'open')
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDNOTESRV)
        # TODO: Fix broken test
        # self.assertEqual(action[3], 'Cleartext submission of password')

if __name__ == '__main__':
    unittest.main()
