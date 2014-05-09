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
from mockito import mock
from model import api
from model.hosts import Host, Interface, Service
from model.workspace import WorkspaceOnCouch, WorkspaceManager, WorkspaceOnFS
from model.common import ModelObjectVuln, ModelObjectVulnWeb
from persistence.orm import WorkspacePersister
import random


from managers.all import CommandManager, CouchdbManager, PersistenceManagerFactory

def new_random_workspace_name():
    return ("aworkspace" + "".join(random.sample([chr(i) for i in range(65, 90)
                                ], 10 ))).lower() 

def create_host(self, host_name="pepito", os="linux"):
    host = Host(host_name, os)
    self.model_controller.addHostSYNC(host)
    return host

def create_interface(self, host, iname="coqiuto", mac="00:03:00:03:04:04"):
    interface = Interface(name=iname, mac=mac)
    self.model_controller.addInterfaceSYNC(host.getName(), interface)
    return interface

def create_service(self, host, interface, service_name = "coquito"):
    service = Service(service_name)
    self.model_controller.addServiceToInterfaceSYNC(host.getID(),
                                interface.getID(), service)
    return service

class VulnerabilityCreationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model_controller = controller.ModelController(mock())
        api.setUpAPIs(cls.model_controller)

    def setUp(self):
        self.wm = WorkspaceManager(self.model_controller, mock(plcore.PluginController))
        self.temp_workspace = self.wm.createWorkspace(new_random_workspace_name(),
                                        workspaceClass=WorkspaceOnCouch) 

        self.wm.setActiveWorkspace(self.temp_workspace)
        WorkspacePersister.stopThreads()

    def tearDown(self):
        # self.wm.removeWorkspace(self.temp_workspace.name)
        pass

    def testAddVulnToHost(self):
        """ This test case creates a host within the Model Controller context
        then adds a VULN"""

        # When
        h = create_host(self) 
        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription', severity='high')
        self.model_controller.addVulnToHostSYNC(h.getID(), vuln)

        # Then
        added_host = self.model_controller.getHost(h.getName())
        vulns = added_host.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')


    def testAddVulnToInterface(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds a VULN"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToInterfaceSYNC(host.getID(),
                                interface.getID(), vuln)

        # Then
        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        vulns = added_interface.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')


    def testAddVulnToService(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds service then a VULN"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)
        service = create_service(self, host, interface)

        vuln = ModelObjectVulnWeb(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                service.getID(), vuln)

        # Then
        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        vulns = added_service.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')

    def testAddVulnWebToHost(self):
        """ This test case creates a host within the Model Controller context
        then adds a VulnWeb"""

        # When
        h = create_host(self) 
        vuln = ModelObjectVulnWeb(name='VulnTest', desc='TestDescription', severity='high')
        self.model_controller.addVulnToHostSYNC(h.getID(), vuln)

        # Then
        added_host = self.model_controller.getHost(h.getName())
        vulns = added_host.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')


    def testAddVulnWebToInterface(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds a VulnWeb"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)

        vuln = ModelObjectVulnWeb(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToInterfaceSYNC(host.getID(),
                                interface.getID(), vuln)

        # Then
        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        vulns = added_interface.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')


    def testAddVulnWebToService(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds service then a VulnWeb"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)
        service = create_service(self, host, interface)

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                service.getID(), vuln)

        # Then
        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        vulns = added_service.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')

    def testStamdarizeNumericVulnSeverity(self):
        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=0)

        self.assertEquals(vuln.severity, 'info',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=1)

        self.assertEquals(vuln.severity, 'low',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=2)

        self.assertEquals(vuln.severity, 'med',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=3)

        self.assertEquals(vuln.severity, 'high',
                    'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=4)

        self.assertEquals(vuln.severity, 'critical', 
                'Vulnerability severity not transformed correctly')


        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=5)

        self.assertEquals(vuln.severity, 'unclassified', 
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity=-1)

        self.assertEquals(vuln.severity, 'unclassified', 
                'Vulnerability severity not transformed correctly')

    def testStamdarizeShortnameVulnSeverity(self):
        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='informational')

        self.assertEquals(vuln.severity, 'info',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='medium')

        self.assertEquals(vuln.severity, 'med',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='highest')

        self.assertEquals(vuln.severity, 'high',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='criticalosiuos')

        self.assertEquals(vuln.severity, 'critical',
                'Vulnerability severity not transformed correctly')

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='tuvieja')

        self.assertEquals(vuln.severity, 'unclassified',
                'Vulnerability severity not transformed correctly')

    def testStandarizeUpdatedSeverity(self):
        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='informational')

        self.assertEquals(vuln.severity, 'info',
                'Vulnerability severity not transformed correctly')

        vuln.updateAttributes(severity='3')
        self.assertEquals(vuln.severity, 'high',
                'Vulnerability severity not transformed correctly')



if __name__ == '__main__':
    unittest.main()

