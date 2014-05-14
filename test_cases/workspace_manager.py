#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
sys.path.append('.')
import model.controller as controller
import plugins.core as plcore
from mockito import mock
from model import api
from model.hosts import Host, Interface, Service
from model.common import (ModelObjectVuln, ModelObjectVulnWeb,
                          ModelObjectNote, ModelObjectCred)
from model.workspace import WorkspaceOnCouch, WorkspaceManager, WorkspaceOnFS
import random
from persistence.orm import WorkspacePersister
from managers.all import CouchdbManager

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


def new_random_workspace_name():
    return ("aworkspace" + "".join(random.sample(
        [chr(i) for i in range(65, 90)], 10))).lower()


def create_host(self, host_name="pepito", os="linux"):
    host = Host(host_name, os)
    self.model_controller.addHostSYNC(host)
    return host


def create_interface(self, host, iname="coquito", mac="00:03:00:03:04:04",
                     ip="127.0.0.1"):
    interface = Interface(name=iname, mac=mac, ipv4_address=ip)
    self.model_controller.addInterfaceSYNC(host.getName(), interface)
    return interface


def create_service(self, host, interface, service_name="coquito", ports=999):
    service = Service(service_name, ports=ports)
    self.model_controller.addServiceToInterfaceSYNC(host.getID(),
                                                    interface.getID(),
                                                    service)
    return service


class TestWorkspaceManager(unittest.TestCase):
    """docstring for TestWorspace"""
    @classmethod
    def setUpClass(cls):
        cls.model_controller = controller.ModelController(mock())
        api.setUpAPIs(cls.model_controller)
        cls.couch_uri = CONF.getCouchURI()
        cls.cdm = CouchdbManager(uri=cls.couch_uri)

    def setUp(self):
        self._couchdb_workspaces = []
        self.wm = WorkspaceManager(self.model_controller,
                                   mock(plcore.PluginController))

    def tearDown(self):
        self.cleanCouchDatabases()

    def cleanCouchDatabases(self):
        try:
            for wname in self._couchdb_workspaces:
                self.cdm.removeWorkspace(wname)
        except Exception as e:
            print e

    def test_switch_workspace_with_objects(self):
        workspace = self.wm.createWorkspace(new_random_workspace_name(),
                                            workspaceClass=WorkspaceOnCouch)
        self._couchdb_workspaces.append(workspace.name)
        self.wm.setActiveWorkspace(workspace)
        WorkspacePersister.stopThreads()

        host1 = create_host(self, "coquito")
        interface1 = create_interface(self, host1, iname="pepito")
        service1 = create_service(self, host1, interface1)

        self.assertIn(host1, self.model_controller.getAllHosts(),
                      "Host not in controller")
        self.assertIn(interface1, host1.getAllInterfaces(),
                      "Interface not in host!")
        self.assertIn(service1, interface1.getAllServices(),
                      "Service not in Interface!")

        workspace2 = self.wm.createWorkspace(new_random_workspace_name(),
                                             workspaceClass=WorkspaceOnCouch)
        self._couchdb_workspaces.append(workspace2.name)
        self.wm.setActiveWorkspace(workspace2)
        WorkspacePersister.stopThreads()

        self.assertNotIn(host1, self.model_controller.getAllHosts(),
                         "Host in controller, should be removed when \
                         switching workspaces")

        self.wm.setActiveWorkspace(workspace)
        WorkspacePersister.stopThreads()
        self.assertIn(host1, self.model_controller.getAllHosts(),
                      "Host not in controller")
        self.assertIn(interface1, host1.getAllInterfaces(),
                      "Interface not in host!")
        self.assertIn(service1, interface1.getAllServices(),
                      "Service not in Interface!")

    def test_remove_active_workspace(self):
        workspace = self.wm.createWorkspace(new_random_workspace_name(),
                                            workspaceClass=WorkspaceOnCouch)

        self.wm.setActiveWorkspace(workspace)
        WorkspacePersister.stopThreads()
        host1 = create_host(self, "coquito")

        self.wm.removeWorkspace(workspace.name)

        hosts_ids = [h.getID() for h in self.model_controller.getAllHosts()]
        self.assertNotIn(host1.getID(), hosts_ids,
                         'Host not removed while removing active workspace')

    def test_remove_active_workspace_fs(self):
        workspace = self.wm.createWorkspace(new_random_workspace_name(),
                                            workspaceClass=WorkspaceOnFS)
        self.wm.setActiveWorkspace(workspace)
        WorkspacePersister.stopThreads()
        host1 = create_host(self, "coquito")

        self.wm.removeWorkspace(workspace.name)

        self.assertNotIn(host1, self.model_controller.getAllHosts(),
                         'Host not removed while removing active workspace')

    def test_remove_another_workspace(self):
        workspace = self.wm.createWorkspace(new_random_workspace_name(),
                                            workspaceClass=WorkspaceOnCouch)

        workspace2 = self.wm.createWorkspace(new_random_workspace_name(),
                                             workspaceClass=WorkspaceOnCouch)
        self._couchdb_workspaces.append(workspace2.name)

        self.wm.setActiveWorkspace(workspace)
        WorkspacePersister.stopThreads()
        create_host(self, "coquito")
        self.wm.setActiveWorkspace(workspace2)
        WorkspacePersister.stopThreads()
        self.wm.removeWorkspace(workspace.name)

        self.assertNotIn(workspace.name, self.wm.getWorkspacesNames(),
                         "Workspace not removed")
        self.assertIn(workspace2.name, self.wm.getWorkspacesNames(),
                      "Workspace removed while removing another workspace")

    def test_load_workspace_on_couch(self):
        """ This test case creates a host within the Model Controller context
        adds an interface to it then adds a VulnWeb"""

        """
        We are going to test this structure:
        host -> interface1 -> service1 -> vuln_web
                                       -> vuln
                                       -> note
                           -> service2 -> vuln
                                       -> vuln
             -> vuln
             -> note
             -> note

             -> interface2 -> service3 -> note
                                       -> credential
                                       -> vuln
                           -> vuln
        """

        workspace = self.wm.createWorkspace(new_random_workspace_name(),
                                            workspaceClass=WorkspaceOnCouch)
        self._couchdb_workspaces.append(workspace.name)
        self.wm.setActiveWorkspace(workspace)
        WorkspacePersister.stopThreads()

        host = create_host(self)
        interface = create_interface(self, host, ip="127.0.0.1")
        interface2 = create_interface(self, host, ip="127.0.0.2")
        service = create_service(self, host, interface, ports=1)
        service2 = create_service(self, host, interface, ports=2)
        service3 = create_service(self, host, interface2, ports=3)

        vulnweb = ModelObjectVulnWeb(name='VulnWebTest',
                                     desc='TestDescription',
                                     severity='high')

        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                                   service.getID(),
                                                   vulnweb)

        vuln = ModelObjectVuln(name='VulnTest', desc='TestDescription',
                               severity='high')
        vuln2 = ModelObjectVuln(name='VulnTest2', desc='TestDescription',
                                severity='high')
        vuln3 = ModelObjectVuln(name='VulnTest3', desc='TestDescription',
                                severity='high')
        vuln4 = ModelObjectVuln(name='VulnTest4', desc='TestDescription',
                                severity='high')
        vuln5 = ModelObjectVuln(name='VulnTest5', desc='TestDescription',
                                severity='high')
        vuln6 = ModelObjectVuln(name='VulnTest6', desc='TestDescription',
                                severity='high')

        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                                   service.getID(),
                                                   vuln)
        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                                   service2.getID(),
                                                   vuln2)
        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                                   service2.getID(),
                                                   vuln3)
        self.model_controller.addVulnToHostSYNC(host.getID(),
                                                vuln4)
        self.model_controller.addVulnToServiceSYNC(host.getID(),
                                                   service3.getID(),
                                                   vuln5)
        self.model_controller.addVulnToInterfaceSYNC(host.getID(),
                                                     interface2.getID(),
                                                     vuln6)

        note = ModelObjectNote(name='NoteTest', text='TestDescription')
        note2 = ModelObjectNote(name='NoteTest2', text='TestDescription')
        note3 = ModelObjectNote(name='NoteTest3', text='TestDescription')
        note4 = ModelObjectNote(name='NoteTest4', text='TestDescription')

        self.model_controller.addNoteToServiceSYNC(host.getID(),
                                                   service.getID(),
                                                   note)
        self.model_controller.addNoteToHostSYNC(host.getID(),
                                                note2)
        self.model_controller.addNoteToHostSYNC(host.getID(),
                                                note3)
        self.model_controller.addNoteToServiceSYNC(host.getID(),
                                                   service3.getID(),
                                                   note4)

        cred = ModelObjectCred(username='user', password='pass')

        self.model_controller.addCredToServiceSYNC(host.getID(),
                                                   service3.getID(),
                                                   cred)

        # First, we test if the structure was correctly created

        # one host with two interfaces, one vuln and two notes

        self.assertEquals(len(self.model_controller.getAllHosts()), 1,
                          "Host not created")
        added_host = self.model_controller.getHost(host.getID())

        self.assertEquals(len(added_host.getAllInterfaces()), 2,
                          "Interfaces not added to Host")
        self.assertEquals(len(added_host.getVulns()), 1,
                          "Vuln not created")
        self.assertEquals(len(added_host.getNotes()), 2,
                          "Notes not created")

        # one interface with two services, and another one
        # with a service and a vuln

        added_interface1 = added_host.getInterface(interface.getID())
        added_interface2 = added_host.getInterface(interface2.getID())

        self.assertEquals(len(added_interface1.getAllServices()), 2,
                          "Services not created")

        self.assertEquals(len(added_interface2.getAllServices()), 1,
                          "Service not created")

        self.assertEquals(len(added_interface2.getVulns()), 1,
                          "Vulns not created")

        # one service with a note, a vuln and a vuln web
        added_service1 = added_interface1.getService(service.getID())
        self.assertEquals(len(added_service1.getNotes()), 1,
                          "Note not created")
        self.assertEquals(len(added_service1.getVulns()), 2,
                          "Vulns not created")
        added_vuln_web = added_service1.getVuln(vulnweb.getID())
        self.assertEquals(added_vuln_web.class_signature, "VulnerabilityWeb",
                          "Not a vuln web")

        # one service with two vulns
        added_service2 = added_interface1.getService(service2.getID())
        self.assertEquals(len(added_service2.getVulns()), 2,
                          "Services not created")

        # one service with a note, a vuln and a credential

        added_service3 = added_interface2.getService(service3.getID())
        self.assertEquals(len(added_service3.getVulns()), 1,
                          "Vuln not created")
        self.assertEquals(len(added_service3.getNotes()), 1,
                          "Note not created")
        self.assertEquals(len(added_service3.getCreds()), 1,
                          "Cred not created")

        # So, now we reload the worskpace and check everything again

        workspace.load()

        # one host with two interfaces, one vuln and two notes

        self.assertEquals(len(self.model_controller.getAllHosts()), 1,
                          "Host not created")
        added_host = self.model_controller.getHost(host.getID())

        self.assertEquals(len(added_host.getAllInterfaces()), 2,
                          "Interfaces not added to Host")
        self.assertEquals(len(added_host.getVulns()), 1,
                          "Vuln not created")
        self.assertEquals(len(added_host.getNotes()), 2,
                          "Notes not created")

        # one interface with two services, and another one
        # with a service and a vuln

        added_interface1 = added_host.getInterface(interface.getID())
        added_interface2 = added_host.getInterface(interface2.getID())

        self.assertEquals(len(added_interface1.getAllServices()), 2,
                          "Services not created")

        self.assertEquals(len(added_interface2.getAllServices()), 1,
                          "Service not created")

        self.assertEquals(len(added_interface2.getVulns()), 1,
                          "Vulns not created")

        # one service with a note, a vuln and a vuln web
        added_service1 = added_interface1.getService(service.getID())
        self.assertEquals(len(added_service1.getNotes()), 1,
                          "Note not created")
        self.assertEquals(len(added_service1.getVulns()), 2,
                          "Vulns not created")
        added_vuln_web = added_service1.getVuln(vulnweb.getID())
        self.assertEquals(added_vuln_web.class_signature, "VulnerabilityWeb",
                          "Not a vuln web")

        # one service with two vulns
        added_service2 = added_interface1.getService(service2.getID())
        self.assertEquals(len(added_service2.getVulns()), 2,
                          "Services not created")

        # one service with a note, a vuln and a credential

        added_service3 = added_interface2.getService(service3.getID())
        self.assertEquals(len(added_service3.getVulns()), 1,
                          "Vuln not created")
        self.assertEquals(len(added_service3.getNotes()), 1,
                          "Note not created")
        self.assertEquals(len(added_service3.getCreds()), 1,
                          "Cred not created")
   

if __name__ == '__main__':
    unittest.main()
