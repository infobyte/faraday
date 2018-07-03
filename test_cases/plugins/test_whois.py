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
from plugins.repo.whois.plugin import CmdWhoisPlugin
from model.common import factory
from persistence.server.models import (
    Vuln,
    Credential,
    VulnWeb,
    Note,
    Host,
    Service,
    ModelBase)


class TestCmdPingPlugin:
    plugin = CmdWhoisPlugin()
    cd = os.path.dirname(os.path.realpath(__file__))
    with open(cd + '/whois_output', 'r') as output:
        outputWhoisInfobyte = output.read()


    def test_Plugin_Calls_createAndAddHost(self, monkeypatch):
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)
        pending_actions = Queue()
        self.plugin.set_actions_queue(pending_actions)
        monkeypatch.setattr(ModelBase, 'getID', lambda _: 1)
        self.plugin.parseOutputString(self.outputWhoisInfobyte)

        actions = defaultdict(list)
        while not pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions[2000][0].name == "205.251.196.172"
        assert actions.keys() == [2000]

        assert len(actions[2000]) == 8
