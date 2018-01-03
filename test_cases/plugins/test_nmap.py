#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import sys
from Queue import Queue
from collections import defaultdict

sys.path.append(os.path.abspath(os.getcwd()))
from plugins.repo.nmap.plugin import NmapPlugin
from model.common import factory
from persistence.server.models import (
    Vuln,
    Credential,
    VulnWeb,
    Note,
    Host,
    Service,
    ModelBase)


class TestNmapXMLParserTest:
    plugin = NmapPlugin()
    outputNmapBlog = ("Starting Nmap 7.12 ( https://nmap.org ) at 2016-05-16 14:56 ART\n"
                      "Nmap scan report for joaquinlp.me (198.38.82.159)\n"
                      "Host is up (0.19s latency).\n"
                      "rDNS record for 198.38.82.159: mocha2005.mochahost.com\n"
                      "Not shown: 956 filtered ports, 31 closed ports\n"
                      "PORT     STATE SERVICE\n"
                      "21/tcp   open  ftp\n"
                      "25/tcp   open  smtp\n"
                      "53/tcp   open  domain\n"
                      "80/tcp   open  http\n"
                      "110/tcp  open  pop3\n"
                      "143/tcp  open  imap\n"
                      "443/tcp  open  https\n"
                      "465/tcp  open  smtps\n"
                      "587/tcp  open  submission\n"
                      "993/tcp  open  imaps\n"
                      "995/tcp  open  pop3s\n"
                      "2525/tcp open  ms-v-worlds\n"
                      "3306/tcp open  mysql\n"
                      "\n"
                      "Nmap done: 1 IP address (1 host up) scanned in 32.05 seconds\n")

    cd = os.path.dirname(os.path.realpath(__file__))
    with open(cd + '/nmap_output_xml', 'r') as output:
        xml_output = output.read()

    def register_factorties(self, monkeypatch):
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)
        self.pending_actions = Queue()
        self.plugin.set_actions_queue(self.pending_actions)
        monkeypatch.setattr(ModelBase, 'getID', lambda _: 1)

    def test_Plugin_Calls_createAndAddHost(self, monkeypatch):
        self.register_factorties(monkeypatch)

        self.plugin.parseOutputString(self.xml_output)
        actions = defaultdict(list)
        while not self.pending_actions.empty():
            action = self.plugin._pending_actions.get(block=True)
            actions[action[0]].append(action[1])

        assert actions[2000][0].name == "198.38.82.159"
        assert actions.keys() ==  [2000, 20008]

        assert len(actions[2000]) == 1
        assert len(actions[20008]) == 13

        assert map(lambda service: service.name, actions[20008]) == [
            'ftp',
            'smtp',
            'domain',
            'http',
            'pop3',
            'imap',
            'https',
            'smtps',
            'submission',
            'imaps',
            'pop3s',
            'ms-v-worlds',
            'mysql'
                                                                     ]

