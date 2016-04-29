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
from plugins.repo.ping.plugin import CmdPingPlugin
from model.common import (
    factory, ModelObjectVuln, ModelObjectCred,
    ModelObjectVulnWeb, ModelObjectNote
)
from model.hosts import (
    Host, Service, Interface
)
from plugins.modelactions import modelactions


class CmdPingPluginTest(unittest.TestCase):
    plugin = CmdPingPlugin()
    outputPingGoogle = ("PING google.com (216.58.222.142) 56(84) bytes of"
                        "data.\n64 bytes from scl03s11-in-f14.1e100.net"
                        "(216.58.222.142): icmp_seq=1 ttl=53 time=28.9 ms")
    def setUp(self):
        factory.register(Host)
        factory.register(Interface)
        factory.register(Service)
        factory.register(ModelObjectVuln)
        factory.register(ModelObjectVulnWeb)
        factory.register(ModelObjectNote)
        factory.register(ModelObjectCred)

    def test_Plugin_Calls_createAndAddHost(self):
        self.plugin.parseOutputString(self.outputPingGoogle)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDHOST)
        self.assertEqual(action[1], "216.58.222.142")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDINTERFACE)
        self.assertEqual(action[2], "216.58.222.142")

if __name__ == '__main__':
    unittest.main()
