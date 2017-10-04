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
from plugins.repo.telnet.plugin import TelnetRouterPlugin
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


class CmdPingPluginTest(unittest.TestCase):
    plugin = TelnetRouterPlugin()
    outputTelnetLocalhost = ("Connection failed: Connection refused\n"
                             "Trying ::1%1...\n"
                             "Trying 127.0.0.1...\n"
                             "Connected to localhost.\n"
                             "Escape character is '^]'.\n"
                             "a\n"
                             "HTTP/1.1 400 Bad Request\n"
                             "Server: MochiWeb/1.0 (Any of you quaids got a smint?)\n"
                             "Date: Mon, 16 May 2016 17:42:18 GMT\n"
                             "Content-Length: 0\n\n"
                             "Connection closed by foreign host.\n")
    def setUp(self):
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)

    def test_Plugin_Calls_createAndAddHost(self):
        self.plugin.parseOutputString(self.outputTelnetLocalhost)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDHOST)
        self.assertEqual(action[1].name, "127.0.0.1")


if __name__ == '__main__':
    unittest.main()
