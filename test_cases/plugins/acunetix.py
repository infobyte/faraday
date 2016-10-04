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
from plugins.repo.acunetix.plugin import AcunetixPlugin
from model.common import (
    factory, ModelObjectVuln, ModelObjectCred,
    ModelObjectVulnWeb, ModelObjectNote
)
from model.hosts import (
    Host, Service, Interface
)
from plugins.modelactions import modelactions


class AcunetixParserTest(unittest.TestCase):

    cd = os.path.dirname(os.path.realpath(__file__))

    def setUp(self):
        self.plugin = AcunetixPlugin()
        factory.register(Host)
        factory.register(Interface)
        factory.register(Service)
        factory.register(ModelObjectVuln)
        factory.register(ModelObjectVulnWeb)
        factory.register(ModelObjectNote)
        factory.register(ModelObjectCred)

    def test_Plugin_creates_apropiate_objects(self):
        self.plugin.processReport(self.cd + '/acunetix_xml')
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDHOST)
        self.assertEqual(action[1], "87.230.29.167")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDINTERFACE)
        self.assertEqual(action[2], "87.230.29.167")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDSERVICEINT)
        self.assertEqual(action[5], ['80'])
        self.assertEqual(action[3], 'http')
        self.assertEqual(action[4], 'tcp')
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDNOTESRV)
        action = self.plugin._pending_actions.get(block=True)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.CADDVULNWEBSRV)
        self.assertEqual(action[3], "ASP.NET error message")

if __name__ == '__main__':
    unittest.main()
