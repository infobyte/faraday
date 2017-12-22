#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from Queue import Queue
from collections import defaultdict

import os
import sys
import unittest

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
    ModelBase)
from plugins.modelactions import modelactions


class TestCmdPingPlugin:
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

        self.plugin.parseOutputString(self.outputTelnetLocalhost)

        actions = defaultdict(list)
        while not pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions[2000][0].name == "127.0.0.1"
        assert actions.keys() == [2000, 20008]

        assert len(actions[2000]) == 1
        assert len(actions[20008]) == 1


if __name__ == '__main__':
    unittest.main()
