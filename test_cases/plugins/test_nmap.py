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
from plugins.repo.nmap.plugin import NmapPlugin
from model.common import factory
from persistence.server.models import (
    Vuln,
    Credential,
    VulnWeb,
    Note,
    Host,
    Service,
)
from plugins.modelactions import modelactions


class NmapXMLParserTest(unittest.TestCase):
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

    def setUp(self):
        factory.register(Host)
        factory.register(Service)
        factory.register(Vuln)
        factory.register(VulnWeb)
        factory.register(Note)
        factory.register(Credential)

    def test_Plugin_Calls_createAndAddHost(self):
        self.plugin.parseOutputString(self.xml_output)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDHOST)
        self.assertEqual(action[1].name, "198.38.82.159")

    def test_Plugin_Calls_createAndAddService(self):
        self.plugin.parseOutputString(self.xml_output)
        action = self.plugin._pending_actions.get(block=True)
        action = self.plugin._pending_actions.get(block=True)
        self.assertEqual(action[0], modelactions.ADDSERVICEINT)
        self.assertEqual(action[3].ports, [25])
        self.assertEqual(action[3].name, 'smtp')
        self.assertEqual(action[3].protocol, 'tcp')


if __name__ == '__main__':
    unittest.main()
