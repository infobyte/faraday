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


def create_interface(self, host, iname="coqiuto", mac="00:03:00:03:04:04"):
    interface = Interface(name=iname, mac=mac)
    self.model_controller.addInterfaceSYNC(host.getName(), interface)
    return interface


def create_service(self, host, interface, service_name="coquito"):
    service = Service(service_name)
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

if __name__ == '__main__':
    unittest.main()
