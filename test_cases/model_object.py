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
from model.common import ModelObjectVuln, ModelObjectVulnWeb, ModelObjectNote
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

class ModelObjectCRUD(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model_controller = controller.ModelController(mock())
        api.setUpAPIs(cls.model_controller)

    def setUp(self):
        self.wm = WorkspaceManager(self.model_controller,
                                    mock(plcore.PluginController))
        self.temp_workspace = self.wm.createWorkspace(
                                        new_random_workspace_name(),
                                        workspaceClass=WorkspaceOnCouch)

        self.wm.setActiveWorkspace(self.temp_workspace)
        WorkspacePersister.stopThreads()

    def tearDown(self):
        self.wm.removeWorkspace(self.temp_workspace.name)

    def testAddHost(self):
        """ This test case creates a host within the Model Controller context
        then checks it's vality"""
        # When
        hostname = 'host'
        _ = create_host(self, host_name=hostname, os='windows')

        # #Then
        added_host = self.model_controller.getHost(hostname)

        self.assertEquals(added_host.getName(), hostname,
                'Saved object name is not correctly saved')


    def testAddVulnToHost(self):
        """ This test case creates a host within the Model Controller context
        then adds a VULN"""

        # When
        h = create_host(self)
        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='high')
        self.model_controller.addVulnToHostSYNC(h.getID(), vuln)

        added_host = self.model_controller.getHost(h.getName())
        vulns = added_host.getVulns()
        #Then
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

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        vulns = added_interface.getVulns()
        # Then
        self.assertIn(vuln, vulns, 'Vuln not added')

    def testAddVulnToService(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds service then a VULN"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)
        service = create_service(self, host, interface)

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                service.getID(), vuln)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        vulns = added_service.getVulns()
        # Then
        self.assertIn(vuln, vulns, 'Vuln not added')


    def testAddVulnWebToHost(self):
        """ This test case creates a host within the Model Controller context
        then adds a VulnWeb"""

        # When
        h = create_host(self)
        vuln = ModelObjectVulnWeb(name='VulnTest', desc='TestDescription',
                                        severity='high')
        self.model_controller.addVulnToHostSYNC(h.getID(), vuln)

        added_host = self.model_controller.getHost(h.getName())
        vulns = added_host.getVulns()
        # Then
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

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        vulns = added_interface.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')

        self.temp_workspace.load()

        # Then
        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        vulns = added_interface.getVulns()
        self.assertIn(vuln.getID(), [v.getID() for v in vulns],
                'Vuln not reloaded')


    def testAddVulnWebToService(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds service then a VulnWeb"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)
        service = create_service(self, host, interface)

        vuln = ModelObjectVulnWeb(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                service.getID(), vuln)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        vulns = added_service.getVulns()
        # Then
        self.assertIn(vuln, vulns, 'Vuln not added')


    def testAddNoteToHost(self):
        """ This test case creates a host within the Model Controller context
        then adds a Note"""

        # When
        h = create_host(self)
        note = ModelObjectNote(name='NoteTest', text='TestDescription')
        self.model_controller.addNoteToHostSYNC(h.getID(), note)

        # Then
        added_host = self.model_controller.getHost(h.getName())
        notes = added_host.getNotes()
        self.assertIn(note, notes, 'Note not added')


    def testAddNoteToInterface(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds a Note"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)

        note = ModelObjectNote(name='NoteTest', text='TestDescription')

        self.model_controller.addNoteToInterfaceSYNC(host.getID(),
                                interface.getID(), note)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        notes = added_interface.getNotes()
        # Then
        self.assertIn(note, notes, 'Note not added')


    def testAddNoteToService(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds service then a Note"""

        # When
        host = create_host(self)
        interface = create_interface(self, host)
        service = create_service(self, host, interface)

        note = ModelObjectNote(name='NoteTest', text='TestDescription')

        self.model_controller.addNoteToServiceSYNC(host.getID(),
                                service.getID(), note)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        notes = added_service.getNotes()
        # Then
        self.assertIn(note, notes, 'Note not added')

    def testDeleteHost(self):
        """ Creates a Host to test it's removal from the controllers list """

        host1 = create_host(self, "coquito")
        hosts_ids = [h.getID() for h in self.model_controller.getAllHosts()]

        self.assertIn(host1.getID(), hosts_ids,
                                "Host not in controller")

        self.model_controller.delHostSYNC(host1.name)

        hosts_ids = [h.getID() for h in self.model_controller.getAllHosts()]
        self.assertNotIn(host1.getID(), hosts_ids,
                                "Host not deleted")

    def testDeleteInterface(self):
        """ Creates a Host and an Interface, then deletes the interface
        to test it's removal from the controllers list """

        host1 = create_host(self, "coquito")
        interface1 = create_interface(self, host1, iname="pepito")

        hosts_ids = [h.getID() for h in self.model_controller.getAllHosts()]
        self.assertIn(host1.getID(), hosts_ids,
                                "Host not in controller")

        host1 = self.model_controller.getHost(host1.getID())

        interfaces_ids = [i.getID() for i in host1.getAllInterfaces()]
        self.assertIn(interface1.getID(), interfaces_ids,
                                "Interface not in host!")

        self.model_controller.delInterfaceSYNC(host1.getID(), "pepito")

        
        interfaces_ids = [i.getID() for i in
                self.model_controller.getHost(host1.getID()).getAllInterfaces()]

        self.assertNotIn(interface1.getID(), interfaces_ids,
                                "Interface not in host!")


    def testDeleteService(self):
        """ Creates a Host an Interface and a Service, then deletes the Service
        to test it's removal from the controllers list """

        host1 = create_host(self, "coquito")
        interface1 = create_interface(self, host1, iname="pepito")
        service1 = create_service(self, host1, interface1)

        hosts_ids = [h.getID() for h in self.model_controller.getAllHosts()]
        self.assertIn(host1.getID(), hosts_ids,
                                "Host not in controller")

        host1 = self.model_controller.getHost(host1.getID())
        interfaces_ids = [i.getID() for i in host1.getAllInterfaces()]
        self.assertIn(interface1.getID(), interfaces_ids,
                                "Interface not in host!")

        services_ids = [s.getID() for s in \
                            self.model_controller.getHost(host1.getID())
                            .getInterface(interface1.getID()).getAllServices()]

        self.assertIn(service1.getID(), services_ids,
                                "Service not in Interface!")

        self.model_controller.delServiceFromInterfaceSYNC(host1.getID(),
                                    interface1.getID(), service1.getID())

        services_ids = [s.getID() for s in \
                            self.model_controller.getHost(host1.getID())
                            .getInterface(interface1.getID()).getAllServices()]

        self.assertNotIn(service1.getID(), services_ids, \
                        "Service not deleted")

if __name__ == '__main__':
    unittest.main()


