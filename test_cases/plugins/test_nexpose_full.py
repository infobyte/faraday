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
    ModelBase)
from plugins.modelactions import modelactions


class TestNexpose:
    cd = os.path.dirname(os.path.realpath(__file__))

    def test_Plugin_creates_apropiate_objects(self, monkeypatch):
        self.plugin = NexposeFullPlugin()
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)
        pending_actions = Queue()
        self.plugin.set_actions_queue(pending_actions)
        monkeypatch.setattr(ModelBase, 'getID', lambda _: 1)
        self.plugin.processReport(self.cd + '/nexpose_full_xml')

        actions = defaultdict(list)
        while not pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions[2000][0].name == "192.168.1.1"
        assert actions.keys() == [2000, 2017, 2019, 2037, 20008]

        assert len(actions[2000]) == 8
        assert len(actions[20008]) == 20
        assert len(actions[2027]) == 0
        assert len(actions[2037]) == 403
        assert len(actions[2039]) == 0



if __name__ == '__main__':
    unittest.main()
