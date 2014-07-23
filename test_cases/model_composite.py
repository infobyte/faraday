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
        self.assertIn(vuln, host.getVulns(), "Vuln not accessible")
        self.assertEquals(len(host.getAllInterfaces()), 1, "Interfaces added is not 1") 

    def testInterfaceWithMultipleChildTypes(self):
        inter = Interface('coco')
        serv = Service('cuca')
        vuln = ModelObjectVuln('vuln')
        inter.addChild(serv.getID(), serv) 
        inter.addChild(vuln.getID(), vuln)

        self.assertEquals(len(inter.getVulns()), 1, "Vulns added is not 1")
        self.assertIn(vuln, inter.getVulns(), "Vuln not accessible")
        self.assertEquals(len(inter.getAllServices()), 1, "Services added is not 1") 

    def testServiceWithMultipleChildTypes(self):
        serv = Service('cuca')
        vuln = ModelObjectVuln('vuln')
        note = ModelObjectNote('nota')
        serv.addChild(note.getID(), note) 
        serv.addChild(vuln.getID(), vuln)

        self.assertEquals(len(serv.getVulns()), 1, "Vulns added is not 1")
        self.assertIn(vuln, serv.getVulns(), "Vuln not accessible")
        self.assertEquals(len(serv.getNotes()), 1, "Notes added is not 1") 
        self.assertIn(note, serv.getNotes(), "Note not accessible")

    def testHostWithCredentials(self):
        host = Host('coco')
        cred = ModelObjectCred('coco', 'coco123') 
        host.addChild(cred.getID(), cred)
        self.assertEquals(len(host.getCreds()), 1, "Creds added is not 1")
        self.assertIn(cred, host.getCreds(), "Cred not accessible")

    def testInterfaceSetServices(self):
        inter = Interface('coco')
        services = []
        for i in range(50, 60):
            services.append(Service('cuca%s' % i,ports=[i]))
        inter.setServices(services)

        self.assertEquals(len(inter.getChildsByType(Service.__name__)), 10, "not all services added")
        for s in services:
            self.assertIn(s, inter.getChildsByType(Service.__name__), "what happened with services?")

    def testHostSetInterfaces(self):
        host = Host('coco')
        interfaces = []
        for i in range(50, 60):
            interfaces.append(Interface('cuca%s' % i, ipv4_address="192.168.0.%d" % i))
        host.setInterfaces(interfaces)

        self.assertEquals(len(host.getChildsByType(Interface.__name__)), 10, "not all interfaces added")
        for s in interfaces:
            self.assertIn(s, host.getChildsByType(Interface.__name__), "what happened with interfaces?")


    def testHostWithCredentialsNewCredMethod(self):
        host = Host('coco')
        host.newCred('coco', 'coco123')
        self.assertEquals(len(host.getCreds()), 1, "Creds added is not 1")

if __name__ == '__main__':
    unittest.main() 




