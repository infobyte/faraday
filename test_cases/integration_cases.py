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
from model.workspace import WorkspaceOnCouch, WorkspaceManager

class TestModelObjectCRUD(TestCase):
    """docstring for TestModelObjectCRUD"""
    def setUp(self):
        self._model_controller = controller.ModelController(mock())
        self.wm = WorkspaceManager(self._model_controller, mock(plcore.PluginController))
        workspace = self.wm.createWorkspace('test_workspace', workspaceClass=WorkspaceOnCouch)
        workspace.setModelController(self._model_controller)
        self._model_controller.setWorkspace(workspace)

        api.setUpAPIs(self._model_controller)

    def tearDown(self):
        c = self.wm.removeWorkspace('test_workspace')

    def create_host(self, host_name="pepito", os="linux"):
        host = Host(host_name, os)
        self._model_controller.addHostSYNC(host)
        return host

    def create_interface(self, host, iname="coqiuto", mac = "00:03:00:03:04:04"):
        interface = Interface(name = iname, mac = mac)
        self._model_controller.addInterfaceSYNC(host.getName(), interface)
        return interface

    def create_service(self, host, interface, service_name = "coquito"):
        service = Service(service_name)
        self._model_controller.addServiceToInterfaceSYNC(host.getID(),
                                    interface.getID(), service)
        return service

    def test_create_and_remove_host_from_controller(self):
        host1 = self.create_host("coquito")
        self.assertIn(host1, self._model_controller.getAllHosts(),
                                "Host not in controller")

        self._model_controller.delHostSYNC(host1.name)

        self.assertNotIn(host1.getID(), self._model_controller.getAllHosts(),
                                "Host not deleted")

    def test_delete_interface(self):
        host1 = self.create_host("coquito")
        interface1 = self.create_interface(host1, iname = "pepito")

        self.assertIn(interface1, host1.getAllInterfaces(),
                                "Interface not in host!")

        self._model_controller.delInterfaceSYNC(host1.getID(), "pepito")
        self.assertNotIn(interface1, host1.getAllInterfaces(),
                                "Interface in host! Not deleted!")
        self.assertIn(host1, self._model_controller.getAllHosts(),
                                'Host removed after interface removal')

    def test_delete_service(self):
        host1 = self.create_host("coquito")
        interface1 = self.create_interface(host1, iname="pepito")
        service1 = self.create_service(host1, interface1)

        self.assertIn(host1, self._model_controller.getAllHosts(),
                                "Host not in controller")
        self.assertIn(interface1, host1.getAllInterfaces(),
                                "Interface not in host!")
        self.assertIn(service1, interface1.getAllServices(),
                                "Service not in Interface!")
        self._model_controller.delServiceFromInterfaceSYNC(host1.getID(),
                                    interface1.getID(), service1.getID())

        self.assertNotIn(service1, self._model_controller.getHost(host1.getID())
                        .getInterface(interface1.getID()).getAllServices(), \
                        "Service not deleted")




if __name__ == '__main__':
    unittest.main()

