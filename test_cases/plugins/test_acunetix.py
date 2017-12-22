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
import pytest

sys.path.append(os.path.abspath(os.getcwd()))
from plugins.repo.acunetix.plugin import AcunetixPlugin
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



class TestAcunetixParser:

    cd = os.path.dirname(os.path.realpath(__file__))



    def test_Plugin_creates_apropiate_objects(self, monkeypatch):
        self.plugin = AcunetixPlugin()
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)

        pending_actions = Queue()
        # getID will wait for faraday-server api response.
        # Since the thread model controller is not running
        # no object will be persisted.
        # The mock is to simulated the api response
        monkeypatch.setattr(ModelBase, 'getID', lambda _: 1)
        self.plugin.set_actions_queue(pending_actions)
        self.plugin.processReport(self.cd + '/acunetix_xml')
        actions = defaultdict(list)
        while not pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions.keys() == [2000, 20008, 2027, 2037, 2039]
        assert len(actions[2000]) == 1
        assert actions[2000][0].name == "5.175.17.140"
        assert len(actions[20008]) == 1
        assert len(actions[2027]) == 1
        assert len(actions[2037]) == 52
        assert len(actions[2039]) == 1

        assert actions[20008][0].ports == [80]
        assert actions[20008][0].name == 'http'
        assert actions[20008][0].protocol == 'tcp'

        assert "ASP.NET error message" in map(lambda vuln_web: vuln_web.name, actions[2037])


if __name__ == '__main__':
    unittest.main()
