#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import unittest
import sys
from Queue import Queue
from collections import defaultdict

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
    ModelBase)
from plugins.modelactions import modelactions


class TestBurp:

    cd = os.path.dirname(os.path.realpath(__file__))


    def test_Plugin_creates_adecuate_objects(self, monkeypatch):
        self.plugin = BurpPlugin()
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)
        pending_actions = Queue()
        self.plugin.set_actions_queue(pending_actions)
        monkeypatch.setattr(ModelBase, 'getID', lambda _: 1)
        self.plugin.processReport(self.cd + '/burp_xml')
        actions = defaultdict(list)
        while not pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions[2000][0].name == "200.20.20.201"
        assert actions.keys() == [2000, 20008, 2027, 2037, 2039]
        assert len(actions[20008]) == 14
        assert len(actions[2027]) == 14
        assert len(actions[2037]) == 14
        assert len(actions[2039]) == 14

        assert all('http' == name for name in map(lambda service: service.name, actions[20008]))
        assert all([80] == ports for ports in map(lambda service: service.ports, actions[20008]))
        assert all('tcp' == protocol for protocol in map(lambda service: service.protocol, actions[20008]))
        assert all('open' for status in map(lambda service: service.status, actions[20008]))

        # self.assertEqual(action[3], 'Cleartext submission of password')

if __name__ == '__main__':
    unittest.main()
