#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import sys
import unittest
from Queue import Queue
from collections import defaultdict

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
    ModelBase)


class TestNessusParser:
    cd = os.path.dirname(os.path.realpath(__file__))

    def test_Plugin_Calls_createAndAddHost(self, monkeypatch):
        self.plugin = NessusPlugin()
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)

        pending_actions = Queue()
        self.plugin.set_actions_queue(pending_actions)
        monkeypatch.setattr(ModelBase, 'getID', lambda _: 1)
        self.plugin.processReport(self.cd + '/nessus_xml')
        actions = defaultdict(list)
        while not pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions[2000][0].name == "12.233.108.201"
        assert actions.keys() == [2017, 20008, 2027, 2000, 2038, 2040]
        assert len(actions[20008]) == 1
        assert len(actions[2027]) == 1
        assert len(actions[2038]) == 1
        assert len(actions[2040]) == 1

        assert actions[2040][0].name == "preprod.boardvantage.net"
        assert actions[2038][0].name == "Nessus SYN scanner"

        assert actions[20008][0].ports == [443]
        assert actions[20008][0].name == 'https?'
        assert actions[20008][0].protocol == 'tcp'



if __name__ == '__main__':
    unittest.main()
