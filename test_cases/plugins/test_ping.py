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
from plugins.repo.ping.plugin import CmdPingPlugin
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
    plugin = CmdPingPlugin()
    outputPingGoogle = ("PING google.com (216.58.222.142) 56(84) bytes of"
                        "data.\n64 bytes from scl03s11-in-f14.1e100.net"
                        "(216.58.222.142): icmp_seq=1 ttl=53 time=28.9 ms")

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
        self.plugin.parseOutputString(self.outputPingGoogle)

        actions = defaultdict(list)
        while not pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions[2000][0].name == "216.58.222.142"
        assert actions.keys() == [2000]

        assert len(actions[2000]) == 1



if __name__ == '__main__':
    unittest.main()
