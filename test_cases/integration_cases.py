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

    def create_host(self, host_name = "pepito", os="linux"):
        host = Host(host_name, os)
        self._model_controller.addHostSYNC(host)
        return host

    def create_interface(self, host, iname = "coqiuto", mac = "00:03:00:03:04:04"):
        interface = Interface(name = iname, mac = mac)
        self._model_controller.addInterfaceSYNC(host.getName(), interface)
        return interface

    def create_service(self, host, interface, service_name = "coquito"):
        service = Service(service_name)
        self._model_controller.addServiceToInterfaceSYNC(host.getID(), interface.getID(), service)
        return service

    def test_create_and_remove_host_from_controller(self):
        h1 = self.create_host("coquito")
        self.assertIn(h1, self._model_controller.getAllHosts(), "Host not in controller")

        self._model_controller.delHostSYNC(h1.name)

        self.assertNotIn(h1.getID(), self._model_controller.getAllHosts(), "Host not deleted")

    def test_delete_interface(self):
        h1 = self.create_host("coquito")
        i1 = self.create_interface(h1, iname = "pepito")

        self.assertIn(i1, h1.getAllInterfaces(), "Interface not in host!")

        self._model_controller.delInterfaceSYNC(h1.getID(), "pepito")
        self.assertNotIn(i1, h1.getAllInterfaces(), "Interface in host! Not deleted!")
        self.assertNotIn(i1, h1.getAllInterfaces(), "Interface in host! Not deleted!")
        self.assertIn(h1, self._model_controller.getAllHosts())

    def test_delete_service(self):
        h1 = self.create_host("coquito")
        i1 = self.create_interface(h1, iname = "pepito")
        s1 = self.create_service(h1, i1)

        self._model_controller.delServiceFromInterfaceSYNC(h1.getID(), i1.getID(), s1.getID())
        self.assertNotIn(s1, self._model_controller.getHost(h1.getID()).getInterface(i1.getID()).getAllServices(), "Service not deleted")


if __name__ == '__main__':
    unittest.main()

