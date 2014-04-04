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
from mockito import mock, when
from model import api
from plugins.core import PluginBase, PluginController
from model.workspace import Workspace
from model.container import ModelObjectContainer
from managers.all import CommandManager


class TestPluginCreateModelObject(TestCase):
    """docstring for TestModelObjectCRUD"""
    def setUp(self):
        self._model_controller = controller.ModelController(mock())
        self.cm = mock(CommandManager)
        when(self.cm).saveCommand().thenReturn(True)
        self._plugin_controller = PluginController("test", {}, self.cm)

        class PluginTest(PluginBase):
            def __init__(self):
                PluginBase.__init__(self)
                self.id = "Test"
                self.name = "Test"

            def parseOutputString(self, output, debug=False):
                pass

        self.workspace = mock(Workspace)
        when(self.workspace).getContainee().thenReturn(ModelObjectContainer())
        self._model_controller.setWorkspace(self.workspace)

        self.plugin = PluginTest()
        api.setUpAPIs(self._model_controller)

        self._plugin_controller.setActivePlugin(self.plugin)

    def test_create_host(self):
        """
        Testing the creation of one host
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        self.assertTrue(h is not None, "host should have an ID")
        self.assertTrue(len(self._model_controller.getAllHosts()) == 1, "The controller should have one host")
        self.assertTrue(self._model_controller.getHost(h) is not None, "The host should be in the controller")

    def test_create_same_host_two_times(self):
        """
        Testing the creation of the same host, two times.
        This simulates two plugins creating the host with the same name
        We should end up with just one host in the controller
        """
        h1 = self.plugin.createAndAddHost("pepito", "linux")
        h2 = self.plugin.createAndAddHost("pepito", "linux")
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        self.assertTrue(len(self._model_controller.getAllHosts()) == 1, "The controller should have just one host")
        self.assertTrue(self._model_controller.getHost(h1) == self._model_controller.getHost(h2), "The host should be the same")

    def test_create_host_with_interface(self):
        """
        Testing the creation of one host, with one interface
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        self.assertTrue(i is not None, "interface should have an ID")
        host = self._model_controller.getHost(h)
        self.assertTrue(len(host.getAllInterfaces()) == 1, "Host should have one interface")
        self.assertTrue(host.getInterface(i) is not None, "The interface should be the one we've just create")

    def test_create_interface_two_times(self):
        """
        Testing the creation of the same interface, two times.
        This simulates two plugins creating the host with the same interface
        We should end up with just one interface in that host
        """
        h1 = self.plugin.createAndAddHost("pepito", "linux")
        i1 = self.plugin.createAndAddInterface(h1, "1.2.3.4")

        h2 = self.plugin.createAndAddHost("pepito", "linux")
        i2 = self.plugin.createAndAddInterface(h2, "1.2.3.4")

        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        self.assertTrue(len(self._model_controller.getAllHosts()) == 1, "The controller should have just one host")
        self.assertTrue(len(self._model_controller.getHost(h1).getAllInterfaces()) == 1, "The host should have just one interface")

    def test_create_host_with_interface_with_service(self):
        """
        Testing the creation of one host, with one interface and one service on that interface
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        s = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['80'])
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        host = self._model_controller.getHost(h)
        interface = host.getInterface(i)
        self.assertTrue(len(interface.getAllServices()) == 1, "The interface should have just one service")
        self.assertTrue(interface.getService(s) is not None, "The service should be the one we've just create")

    def test_create_two_services_different_names_equal_port(self):
        """
        Testing the creation of two services with different names but same protocol and port
        The result should only one services being created, since both have the same id
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        s1 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['80'])
        s2 = self.plugin.createAndAddServiceToInterface(h, i, "test", protocol="tcp", ports=['80'])
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        host = self._model_controller.getHost(h)
        interface = host.getInterface(i)
        self.assertEqual(s1, s2, "Both services should have the same id")
        self.assertTrue(len(interface.getAllServices()) == 1, "The interface should have just one service")

    def test_create_two_services_same_names_different_port(self):
        """
        Testing the creation of two services with same names but different port
        The result should only two services being created, since both have the different ids
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        s1 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['80'])
        s2 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['443'])
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        host = self._model_controller.getHost(h)
        interface = host.getInterface(i)
        self.assertNotEqual(s1, s2, "Both services should have the same id")
        self.assertTrue(len(interface.getAllServices()) == 2, "The interface should have two services")

    def test_create_vuln_to_service(self):
        """
        Testing the creation of a vuln to a service
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        s1 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['80'])
        s2 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['443'])
        v = self.plugin.createAndAddVulnToService(h, s1, "vuln1", "descripcion")
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        host = self._model_controller.getHost(h)
        interface = host.getInterface(i)
        service1 = interface.getService(s1)
        service2 = interface.getService(s2)
        self.assertTrue(len(service1.getVulns()) == 1, "The service should have one vuln")
        self.assertTrue(service1.getVuln(v) is not None, "The vuln should be the one we've just create")
        self.assertTrue(len(service2.getVulns()) == 0, "The service should't have any vuln")

    def test_create_note_to_service(self):
        """
        Testing the creation of a vuln to a service
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        s1 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['80'])
        s2 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['443'])
        n = self.plugin.createAndAddNoteToService(h, s1, "note1", "desc1")
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        host = self._model_controller.getHost(h)
        interface = host.getInterface(i)
        service1 = interface.getService(s1)
        service2 = interface.getService(s2)
        self.assertTrue(len(service1.getNotes()) == 1, "The service should have one vuln")
        self.assertTrue(service1.getNote(n) is not None, "The vuln should be the one we've just create")
        self.assertTrue(len(service2.getNotes()) == 0, "The service should't have any vuln")

    def test_create_note_to_note_service(self):
        """
        Testing the creation of a vuln to a service
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        s1 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['80'])
        s2 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['443'])
        n = self.plugin.createAndAddNoteToService(h, s1, "note1", "desc1")
        n2 = self.plugin.createAndAddNoteToNote(h, s1, n, "note2", "desc2")
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        host = self._model_controller.getHost(h)
        interface = host.getInterface(i)
        service1 = interface.getService(s1)
        service2 = interface.getService(s2)
        note1 = service1.getNote(n)
        self.assertTrue(service1.getNote(n) is not None, "The note should be the one we've just create")
        self.assertTrue(len(note1.getNotes()) == 1, "The note should have a nested note")

    def test_create_cred_to_service(self):
        """
        Testing the creation of a vuln to a service
        """
        h = self.plugin.createAndAddHost("pepito", "linux")
        i = self.plugin.createAndAddInterface(h, "1.2.3.4")
        s1 = self.plugin.createAndAddServiceToInterface(h, i, "unknown", protocol="tcp", ports=['80'])
        c = self.plugin.createAndAddCredToService(h, s1, "user", "pass")
        self._plugin_controller.onCommandFinished()
        self._model_controller.processAllPendingActions()
        
        host = self._model_controller.getHost(h)
        interface = host.getInterface(i)
        service1 = interface.getService(s1)
        cred = service1.getCred(c)
        self.assertTrue(service1.getCred(c) is not None, "The cred should be the one we've just create")
        self.assertTrue(len(service1.getCreds()) == 1, "The service should have a nested note")

if __name__ == '__main__':
    unittest.main()