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

from model.visitor import VulnsLookupVisitor
import test_cases.common as test_utils


from managers.all import CommandManager, CouchdbManager, PersistenceManagerFactory

class ModelObjectCRUD(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model_controller = controller.ModelController(mock())
        api.setUpAPIs(cls.model_controller)

    def setUp(self):
        self.wm = WorkspaceManager(self.model_controller,
                                    mock(plcore.PluginController))
        self.temp_workspace = self.wm.createWorkspace(
                                        test_utils.new_random_workspace_name(),
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
        _ = test_utils.create_host(self, host_name=hostname, os='windows')

        # #Then
        added_host = self.model_controller.getHost(hostname)

        self.assertEquals(added_host.getName(), hostname,
                'Saved object name is not correctly saved')


    def testAddVulnToHost(self):
        """ This test case creates a host within the Model Controller context
        then adds a VULN"""

        # When
        h = test_utils.create_host(self)
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
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)

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
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)
        service = test_utils.create_service(self, host, interface)

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
        h = test_utils.create_host(self)
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
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)

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
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)
        service = test_utils.create_service(self, host, interface)

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
        h = test_utils.create_host(self)
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
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)

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
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)
        service = test_utils.create_service(self, host, interface)

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

        host1 = test_utils.create_host(self, "coquito")
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

        host1 = test_utils.create_host(self, "coquito")
        interface1 = test_utils.create_interface(self, host1, iname="pepito")

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

        host1 = test_utils.create_host(self, "coquito")
        interface1 = test_utils.create_interface(self, host1, iname="pepito")
        service1 = test_utils.create_service(self, host1, interface1)

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

    def testDeleteVulnFromHost(self):
        """ Creates a Host adds a Vuln then removes """

        host1 = test_utils.create_host(self, "coquito")

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToHostSYNC(host1.getID(), vuln)

        hosts_ids = [h.getID() for h in self.model_controller.getAllHosts()]

        self.assertIn(host1.getID(), hosts_ids,
                                "Host not in controller")

        self.model_controller.delVulnFromHostSYNC(host1.getID(), vuln.getID())

        added_host = self.model_controller.getHost(host1.getName())

        self.assertNotIn(vuln, added_host.getVulns(), 'Vuln not removed')


    def testDelVulnFromInterface(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds a VULN"""

        # When
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToInterfaceSYNC(host.getID(),
                                interface.getID(), vuln)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        vulns = added_interface.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')

        # Then
        self.model_controller.delVulnFromInterfaceSYNC(host.getID(),
                            interface.getID(), vuln.getID())

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        vulns = added_interface.getVulns()

        self.assertNotIn(vuln, vulns, 'Vuln not removed')



    def testDelVulnFromService(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds service then a Vuln, then removes the
        Vuln"""

        # When
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)
        service = test_utils.create_service(self, host, interface)

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                service.getID(), vuln)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        vulns = added_service.getVulns()
        self.assertIn(vuln, vulns, 'Vuln not added')

        # Then

        self.model_controller.delVulnFromServiceSYNC(host.getID(),
                            service.getID(), vuln.getID())

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        vulns = added_service.getVulns()
        self.assertNotIn(vuln, vulns, 'Vuln not removed')

    def testDeleteNoteFromHost(self):
        """ Creates a Host adds a Note then removes """

        host1 = test_utils.create_host(self, "coquito")

        note = ModelObjectNote(name='NoteTest', text='TestDescription')

        self.model_controller.addNoteToHostSYNC(host1.getID(), note)

        hosts_ids = [h.getID() for h in self.model_controller.getAllHosts()]

        self.assertIn(host1.getID(), hosts_ids,
                                "Host not in controller")

        self.model_controller.delNoteFromHostSYNC(host1.getID(), note.getID())

        added_host = self.model_controller.getHost(host1.getName())

        self.assertNotIn(note, added_host.getNotes(), 'Note not removed')


    def testDelNoteFromInterface(self):
        """ Creates a Hosts, adds an Interface and a Note, then removes the
        note """

        # When
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)

        note = ModelObjectNote(name='NoteTest', text='TestDescription')

        self.model_controller.addNoteToInterfaceSYNC(host.getID(),
                                interface.getID(), note)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        notes = added_interface.getNotes()
        self.assertIn(note, notes, 'Note not added')

        # Then
        self.model_controller.delNoteFromInterfaceSYNC(host.getID(),
                            interface.getID(), note.getID())

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        notes = added_interface.getNotes()

        self.assertNotIn(note, notes, 'Note not removed')



    def testDelNoteFromService(self):
        """ Creates a Hosts, adds an Interface, a Service and a Note, then removes the
        note """

        # When
        host = test_utils.create_host(self)
        interface = test_utils.create_interface(self, host)
        service = test_utils.create_service(self, host, interface)

        note = ModelObjectNote(name='NoteTest', text='TestDescription')

        self.model_controller.addNoteToServiceSYNC(host.getID(),
                                service.getID(), note)

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        notes = added_service.getNotes()
        self.assertIn(note, notes, 'Note not added')

        # Then

        self.model_controller.delNoteFromServiceSYNC(host.getID(),
                            service.getID(), note.getID())

        added_host = self.model_controller.getHost(host.getName())
        added_interface = added_host.getInterface(interface.getID())
        added_service = added_interface.getService(service.getID())
        notes = added_service.getNotes()
        self.assertNotIn(note, notes, 'Note not removed')

    def testVulnHostLookup(self):
        host = test_utils.create_host(self)
        vuln = test_utils.create_host_vuln(self, host, 'vuln', 'desc', 'high')
        visitor = VulnsLookupVisitor(vuln.getID())
        host.accept(visitor)


        self.assertEquals(len(visitor.parents[0]), 1,
                "object hierarchy should be only host")
        self.assertIn(vuln, visitor.vulns)

    def testVulnInterfaceLookup(self):
        host = test_utils.create_host(self)
        inter = test_utils.create_interface(self, host)
        vuln = test_utils.create_int_vuln(self, host, inter, 'vuln', 'desc', 'high')
        visitor = VulnsLookupVisitor(vuln.getID())
        host.accept(visitor) 

        self.assertEquals(len(visitor.parents[0]), 2,
                "object hierarchy should be host and interface")
        self.assertIn(vuln, visitor.vulns)

    def testVulnServiceLookup(self):
        host = test_utils.create_host(self)
        inter = test_utils.create_interface(self, host)
        service = test_utils.create_service(self, host, inter)
        vuln = test_utils.create_serv_vuln(self, host, service, 'vuln', 'desc', 'high')
        visitor = VulnsLookupVisitor(vuln.getID())
        host.accept(visitor) 

        self.assertEquals(len(visitor.parents[0]), 3,
                "object hierarchy should be host, interface and service")
        self.assertIn(vuln, visitor.vulns)

    def testMultipleVulnLookup(self):
        host = test_utils.create_host(self)
        inter = test_utils.create_interface(self, host)
        service = test_utils.create_service(self, host, inter)
        vuln = test_utils.create_serv_vuln(self, host, service, 'vuln', 'desc', 'high')
        vuln2 = test_utils.create_int_vuln(self, host, inter, 'vuln', 'desc', 'high')
        visitor = VulnsLookupVisitor(vuln.getID())
        host.accept(visitor) 

        parents1 = visitor.parents[0]
        parents2 = visitor.parents[1]

        self.assertIn(host, parents1,
                "Host should be in parents")

        self.assertIn(host, parents2,
                "Host should be in parents")

        self.assertIn(inter, parents2,
                "Interface should be in parents")

        self.assertIn(inter, parents2,
                "Interface should be in parents")

if __name__ == '__main__':
    unittest.main()


