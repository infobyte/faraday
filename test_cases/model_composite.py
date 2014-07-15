#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from unittest import TestCase
import unittest
import sys
sys.path.append('.')
import model.controller as controller
import plugins.core as plcore
from mockito import mock, verify, when, any
from model import api
from model.hosts import Host, Interface, Service
from model.workspace import WorkspaceOnCouch, WorkspaceManager, WorkspaceOnFS
from model.common import ModelObjectVuln, ModelObjectVulnWeb, ModelObjectNote, ModelComposite, ModelObjectCred
from persistence.orm import WorkspacePersister
import random

from model.visitor import VulnsLookupVisitor
import test_cases.common as test_utils

from managers.all import CommandManager, CouchdbManager, PersistenceManagerFactory

class ModelObjectComposite(unittest.TestCase):

    def testAddInterfaceToHost(self): 
        host = Host('coco')
        inter = Interface('cuca')
        host.addChild(inter.getID(), inter)

        self.assertIn(inter, host.childs.values(), 'Interface not in childs')
        self.assertIn(inter, host.getAllInterfaces(), 'Interface not accessible')

    def testAddServiceToInterface(self):
        interface = Interface('coco')
        serv = Service('cuca')
        interface.addChild(serv.getID(), serv)

        self.assertIn(serv, interface.childs.values(), 'Service not in childs')
        self.assertIn(serv, interface.getAllServices(), 'Service not accessible')

    def testAddVulnToInterface(self):
        serv = Service('cuca')
        vuln = ModelObjectVuln('vuln')
        serv.addChild(vuln.getID(), vuln)

        self.assertIn(vuln, serv.childs.values(), 'Vuln not in childs')
        self.assertIn(vuln, serv.getVulns(), 'Vuln not accessible')

    def testHostWithMultipleChildTypes(self):
        host = Host('coco')
        inter = Interface('cuca')
        vuln = ModelObjectVuln('vuln')
        host.addChild(inter.getID(), inter) 
        host.addChild(vuln.getID(), vuln)

        self.assertEquals(len(host.getVulns()), 1, "Vulns added is not 1")
        self.assertEquals(len(host.getAllInterfaces()), 1, "Interfaces added is not 1") 

    def testInterfaceWithMultipleChildTypes(self):
        inter = Interface('coco')
        serv = Service('cuca')
        vuln = ModelObjectVuln('vuln')
        inter.addChild(serv.getID(), serv) 
        inter.addChild(vuln.getID(), vuln)

        self.assertEquals(len(inter.getVulns()), 1, "Vulns added is not 1")
        self.assertEquals(len(inter.getAllServices()), 1, "Services added is not 1") 

if __name__ == '__main__':
    unittest.main() 




