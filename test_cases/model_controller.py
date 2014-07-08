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
from model.common import ModelObjectVuln, ModelObjectVulnWeb, ModelObjectNote, ModelComposite
from persistence.orm import WorkspacePersister
import random

from model.visitor import VulnsLookupVisitor
import test_cases.common as test_utils

from managers.all import CommandManager, CouchdbManager, PersistenceManagerFactory

class ModelObjectControllerUnitTest(unittest.TestCase):
    # TODO: Notifier goes into mapper?

    def testAddHostGetsMapperDispatchSave(self): 
        host = Host('coco')

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(host).thenReturn(objectMapper)
        when(objectMapper).saveObject(host).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addHostSYNC(host)
        verify(mappersManager).getMapper(host)
        verify(objectMapper).saveObject(host)

    def testAddInterfaceGetsMapperDispatchSave(self): 
        host = Host('coco')
        interface = Interface("int_mock0") 

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(interface).thenReturn(objectMapper)
        when(objectMapper).saveObject(interface).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addInterfaceSYNC(host.getID(), interface)
        verify(mappersManager).getMapper(interface)
        verify(objectMapper).saveObject(interface)

    def testAddObjectSavesChildInParent(self): 
        host = Host('coco')
        interface = Interface("int_mock0") 

        mappersManager = self.createMapperMock()
        objectMapper = mock()

        when(mappersManager).getMapper(interface).thenReturn(objectMapper)
        when(objectMapper).saveObject(interface).thenReturn(True) 
        when(mappersManager).findObject(host.getID()).thenReturn(host)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addInterfaceSYNC(host.getID(), interface)
        verify(mappersManager).getMapper(interface)
        verify(objectMapper).saveObject(interface)

        self.assertEquals(interface, host.findChild(interface.getID()), 
                "Orphan child, what happen papi?")

    def testAddServiceGetsMapperDispatchSave(self): 
        interface = Interface("int_mock0") 
        service = Service("servi")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(service).thenReturn(objectMapper)
        when(objectMapper).saveObject(service).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addServiceToInterfaceSYNC(None, interface.getID(), service)

        verify(mappersManager).getMapper(service)
        verify(objectMapper).saveObject(service)

    def testAddVulnToServiceGetsMapperDispatchSave(self): 
        service = Service("servi")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln).thenReturn(objectMapper)
        when(objectMapper).saveObject(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToServiceSYNC(None, service.getID(), vuln)

        verify(mappersManager).getMapper(vuln)
        verify(objectMapper).saveObject(vuln)

    def testAddVulnToInterfaceGetsMapperDispatchSave(self): 
        interface = Interface("int0")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln).thenReturn(objectMapper)
        when(objectMapper).saveObject(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToServiceSYNC(None, interface.getID(), vuln)

        verify(mappersManager).getMapper(vuln)
        verify(objectMapper).saveObject(vuln)

    def testAddVulnToHostGetsMapperDispatchSave(self): 
        host = Host("pepito")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln).thenReturn(objectMapper)
        when(objectMapper).saveObject(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToHostSYNC(host.getID(), vuln)

        verify(mappersManager).getMapper(vuln)
        verify(objectMapper).saveObject(vuln)

    def testAddNoteToServiceGetsMapperDispatchSave(self): 
        service = Service("servi")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note).thenReturn(objectMapper)
        when(objectMapper).saveObject(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceSYNC(None, service.getID(), note)

        verify(mappersManager).getMapper(note)
        verify(objectMapper).saveObject(note)

    def testAddNoteToInterfaceGetsMapperDispatchSave(self): 
        interface = Interface("int0")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note).thenReturn(objectMapper)
        when(objectMapper).saveObject(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceSYNC(None, interface.getID(), note)

        verify(mappersManager).getMapper(note)
        verify(objectMapper).saveObject(note)

    def testAddNoteToHostGetsMapperDispatchSave(self): 
        host = Host("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note).thenReturn(objectMapper)
        when(objectMapper).saveObject(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToHostSYNC(host.getID(), note)

        verify(mappersManager).getMapper(note)
        verify(objectMapper).saveObject(note)

    def testAddNoteToNoteGetsMapperDispatchSave(self): 
        host = Host("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note).thenReturn(objectMapper)
        when(objectMapper).saveObject(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToNoteSYNC(note.getID(), note)

        verify(mappersManager).getMapper(note)
        verify(objectMapper).saveObject(note)

    def testAddSavesObjectNameInTrie(self):
        host = Host('coco')

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        triemock = mock()

        when(mappersManager).getMapper(host).thenReturn(objectMapper)
        when(objectMapper).saveObject(host).thenReturn(True)
        when(triemock).addWord(host.getName()).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)
        model_controller.treeWordsTries = triemock

        model_controller.addHostSYNC(host)

        verify(mappersManager).getMapper(host)
        verify(objectMapper).saveObject(host)
        verify(triemock).addWord(host.getName())


    def createMapperMock(self):
        map_mock = mock()
        when(map_mock).findObject(any()).thenReturn(mock())
        return map_mock



 # def addHostSYNC(self, host, category=None, update=False, old_hostname=None):
 # def addInterfaceSYNC(self, hostId, interface, update=False):
 # def addServiceToInterfaceSYNC(self, host_id, interface_id, newService): 
 # def addVulnToServiceSYNC
 #  def addVulnWebToServiceSYNC(self, host, srvname, newVuln):

 #  def addVulnToInterfaceSYNC(self, host, intname, newVuln):

 # def addApplicationSYNC(self, host, application): Should?

 # def addServiceToApplicationSYNC(self, host, appname, newService):

 #  def addVulnToApplicationSYNC(self, host, appname, newVuln):
 #  def addVulnToHostSYNC(self, host, newVuln):
 #  def addVulnToServiceSYNC(self, host, srvname, newVuln):
 #  def addVulnSYNC(self, model_object, newVuln):

 #  def addNoteToInterfaceSYNC(self, host, intname, newNote):
 #  def addNoteToApplicationSYNC(self, host, appname, newNote):
 #  def addNoteToHostSYNC(self, host, newNote):
 #  def addNoteToServiceSYNC(self, host, srvname, newNote):
 #  def addNoteSYNC(self, model_object, newNote):

 #  def addCredToServiceSYNC(self, host, srvname, newCred):
 #  def addCredSYNC(self, model_object, newCred):


if __name__ == '__main__':
    unittest.main() 

