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
# module's path has a dash (-) in it, so we need to do this...
import importlib
plugin = importlib.import_module('plugins.repo.nexpose-full.plugin')
NexposeFullPlugin = plugin.NexposeFullPlugin
from model.common import factory
from persistence.server.models import (
    Vuln,
    Credential,
    VulnWeb,
    Note,
    Host,
    Service,
    Interface
)
from plugins.modelactions import modelactions


class NexposeTest(unittest.TestCase):
    cd = os.path.dirname(os.path.realpath(__file__))

    def setUp(self):
        self.plugin = NexposeFullPlugin()
        factory.register(Host)
        factory.register(Interface)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)

    def test_Plugin_creates_apropiate_objects(self):
        self.plugin.processReport(self.cd + '/nexpose_full_xml')
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDHOST)
        self.assertEqual(action[1].name, "192.168.1.1")
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDINTERFACE)
        self.assertEqual(action[2].name, "192.168.1.1")
        for i in range(131):
            action = self.plugin._pending_actions.get(block=True)
            if type(action[2]) in [Vuln, VulnWeb]:
                assert action[0] == modelactions.ADDVULNHOST
            elif type(action[-1]) == Service:
                assert action[0] == modelactions.ADDSERVICEINT
        action = self.plugin._pending_actions.get(block=True)
        assert action[0] == modelactions.ADDVULNSRV


if __name__ == '__main__':
    unittest.main()
