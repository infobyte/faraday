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
from plugins.repo.whois.plugin import CmdWhoisPlugin
from model.common import (
    factory, ModelObjectVuln, ModelObjectCred,
    ModelObjectVulnWeb, ModelObjectNote
)
from model.hosts import (
    Host, Service, Interface
)
from plugins.modelactions import modelactions


class CmdPingPluginTest(unittest.TestCase):
    plugin = CmdWhoisPlugin()
    cd = os.path.dirname(os.path.realpath(__file__))
    with open(cd + '/whois_output', 'r') as output:
        outputWhoisInfobyte = output.read()

    def setUp(self):
        factory.register(Host)
        factory.register(Interface)
        factory.register(Service)
        factory.register(ModelObjectVuln)
        factory.register(ModelObjectVulnWeb)
        factory.register(ModelObjectNote)
        factory.register(ModelObjectCred)

    def test_Plugin_Calls_createAndAddHost(self):
        self.plugin.parseOutputString(self.outputWhoisInfobyte)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDHOST)
        self.assertEqual(action[1], "205.251.196.172")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDINTERFACE)
        self.assertEqual(action[2], "205.251.196.172")

if __name__ == '__main__':
    unittest.main()
