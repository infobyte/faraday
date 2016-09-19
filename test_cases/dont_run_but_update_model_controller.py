#!/usr/bin/python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
sys.path.append('.')
import model.controller as controller
from mockito import mock, verify, when, any
from model.hosts import Host, Interface, Service
from model.common import ModelObjectVuln, ModelObjectVulnWeb, ModelObjectNote, ModelObjectCred


class ModelObjectControllerUnitTest(unittest.TestCase):
    # TODO: Notifier goes into mapper?

    def testAddHostGetsMapperDispatchSaveSYNC(self): 
        host = Host('coco')

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(host.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(host).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addHostSYNC(host)
        verify(mappersManager).getMapper(host.class_signature)
        verify(objectMapper).save(host)

    def testAddHostGetsMapperDispatchSaveASYNC(self): 
        host = Host('coco')

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(host.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(host).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addHostASYNC(host)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(host.class_signature)
        verify(objectMapper).save(host)

    def testAddInterfaceGetsMapperDispatchSaveSYNC(self): 
        host = Host('coco')
        interface = Interface("int_mock0") 

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(interface.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(interface).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addInterfaceSYNC(host.getID(), interface)
        verify(mappersManager).getMapper(interface.class_signature)
        verify(objectMapper).save(interface)

    def testAddInterfaceGetsMapperDispatchSaveASYNC(self): 
        host = Host('coco')
        interface = Interface("int_mock0") 

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(interface.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(interface).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addInterfaceASYNC(host.getID(), interface)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(interface.class_signature)
        verify(objectMapper).save(interface)

    def testAddObjectSavesChildInParent(self): 
        host = Host('coco')
        interface = Interface("int_mock0") 

        mappersManager = self.createMapperMock()
        objectMapper = mock()

        when(mappersManager).getMapper(interface.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(interface).thenReturn(True) 
        when(mappersManager).find(host.getID()).thenReturn(host)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addInterfaceSYNC(host.getID(), interface)
        verify(mappersManager).getMapper(interface.class_signature)
        verify(objectMapper).save(interface)

        self.assertEquals(interface, host.findChild(interface.getID()), 
                "Orphan child, what happen papi?")

    def testAddServiceGetsMapperDispatchSaveSYNC(self): 
        interface = Interface("int_mock0") 
        service = Service("servi")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(service.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(service).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addServiceToInterfaceSYNC(None, interface.getID(), service)

        verify(mappersManager).getMapper(service.class_signature)
        verify(objectMapper).save(service)

    def testAddServiceGetsMapperDispatchSaveASYNC(self): 
        interface = Interface("int_mock0") 
        service = Service("servi")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(service.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(service).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addServiceToInterfaceASYNC(None, interface.getID(), service)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(service.class_signature)
        verify(objectMapper).save(service)

    def testAddVulnToServiceGetsMapperDispatchSaveSYNC(self): 
        service = Service("servi")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToServiceSYNC(None, service.getID(), vuln)

        verify(mappersManager).getMapper(vuln.class_signature)
        verify(objectMapper).save(vuln)

    def testAddVulnToServiceGetsMapperDispatchSaveASYNC(self): 
        service = Service("servi")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToServiceASYNC(None, service.getID(), vuln)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(vuln.class_signature)
        verify(objectMapper).save(vuln)

    def testAddVulnToInterfaceGetsMapperDispatchSaveSYNC(self): 
        interface = Interface("int0")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToInterfaceSYNC(None, interface.getID(), vuln)

        verify(mappersManager).getMapper(vuln.class_signature)
        verify(objectMapper).save(vuln)

    def testAddVulnToInterfaceGetsMapperDispatchSaveASYNC(self): 
        interface = Interface("int0")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToInterfaceASYNC(None, interface.getID(), vuln) 
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(vuln.class_signature)
        verify(objectMapper).save(vuln)

    def testAddVulnToHostGetsMapperDispatchSaveSYNC(self): 
        host = Host("pepito")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToHostSYNC(host.getID(), vuln)

        verify(mappersManager).getMapper(vuln.class_signature)
        verify(objectMapper).save(vuln)

    def testAddVulnToHostGetsMapperDispatchSaveASYNC(self): 
        host = Host("pepito")
        vuln = ModelObjectVuln("a_vuln")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(vuln.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(vuln).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addVulnToHostASYNC(host.getID(), vuln)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(vuln.class_signature)
        verify(objectMapper).save(vuln)

    def testAddNoteToServiceGetsMapperDispatchSaveSYNC(self): 
        service = Service("servi")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceSYNC(None, service.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToServiceGetsMapperDispatchSaveASYNC(self): 
        service = Service("servi")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceASYNC(None, service.getID(), note)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToVulnGetsMapperDispatchSave(self): 
        vuln = ModelObjectVuln('a vuln')
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceSYNC(None, vuln.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToServiceGetsMapperDispatchSaveSYNC(self): 
        service = Service("servi")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceSYNC(None, service.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToServiceGetsMapperDispatchSaveASYNC(self): 
        service = Service("servi")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceASYNC(None, service.getID(), note)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToInterfaceGetsMapperDispatchSaveSYNC(self): 
        interface = Interface("int0")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceSYNC(None, interface.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToInterfaceGetsMapperDispatchSaveASYNC(self): 
        interface = Interface("int0")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToServiceASYNC(None, interface.getID(), note)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToHostGetsMapperDispatchSaveSYNC(self): 
        host = Host("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToHostSYNC(host.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToHostGetsMapperDispatchSaveASYNC(self): 
        host = Host("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToHostASYNC(host.getID(), note)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToInterfaceGetsMapperDispatchSaveSYNC(self): 
        interface = Interface("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToInterfaceSYNC(None, interface.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToInterfaceGetsMapperDispatchSaveASYNC(self): 
        interface = Interface("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToInterfaceASYNC(None, interface.getID(), note) 
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToNoteGetsMapperDispatchSaveSYNC(self): 
        host = Host("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToNoteSYNC(note.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddNoteToNoteGetsMapperDispatchSaveASYNC(self): 
        host = Host("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteToNoteASYNC(None, None, note.getID(), note)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def testAddSavesObjectNameInTrie(self):
        host = Host('coco')

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        triemock = mock()

        when(mappersManager).getMapper(host.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(host).thenReturn(True)
        when(triemock).addWord(host.getName()).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)
        model_controller.treeWordsTries = triemock

        model_controller.addHostSYNC(host)

        verify(mappersManager).getMapper(host.class_signature)
        verify(objectMapper).save(host)
        verify(triemock).addWord(host.getName())

    def testAddNoteToModelObjectSYNC(self): 
        host = Host("pepito")
        note = ModelObjectNote("a_note")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(note.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(note).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addNoteSYNC(host.getID(), note)

        verify(mappersManager).getMapper(note.class_signature)
        verify(objectMapper).save(note)

    def createMapperMock(self):
        map_mock = mock()
        when(map_mock).find(any()).thenReturn(mock())
        when(map_mock).find(None).thenReturn(None)
        return map_mock

    def testAddCredGetsMapperDispatchSaveSYNC(self): 
        host = Host("pepito")
        cred = ModelObjectCred("usr", "pass")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(cred.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(cred).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addCredSYNC(cred.getID(), cred)

        verify(mappersManager).getMapper(cred.class_signature)
        verify(objectMapper).save(cred)


    def testAddCredToServiceGetsMapperDispatchSaveSYNC(self): 
        service = Service("pepito")
        cred = ModelObjectCred("usr", "pass")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(cred.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(cred).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addCredToServiceSYNC(None, cred.getID(), cred)

        verify(mappersManager).getMapper(cred.class_signature)
        verify(objectMapper).save(cred)

    def testAddCredToServiceGetsMapperDispatchSaveASYNC(self): 
        service = Service("pepito")
        cred = ModelObjectCred("usr", "pass")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(cred.class_signature).thenReturn(objectMapper)
        when(objectMapper).save(cred).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addCredToServiceASYNC(None, cred.getID(), cred)
        model_controller.processAllPendingActions()

        verify(mappersManager).getMapper(cred.class_signature)
        verify(objectMapper).save(cred)

    def testDeleteHostObjectDispatchRemoveSYNC(self):
        host = Host("coquito")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).find(host.getID()).thenReturn(host)
        when(mappersManager).remove(host.getID()).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager) 
        model_controller.delHostSYNC(host.getID()) 
        verify(mappersManager).remove(host.getID())
        verify(mappersManager).find(host.getID())

    def testDeleteHostObjectDispatchRemoveASYNC(self):
        host = Host("coquito")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).find(host.getID()).thenReturn(host)
        when(mappersManager).remove(host.getID()).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager) 
        model_controller.delHostASYNC(host.getID()) 
        model_controller.processAllPendingActions()

        verify(mappersManager).remove(host.getID())

    def testDeleteModelObjectRemovesChildFromParentSYNC(self): 
        host = Host('coco')
        interface = Interface("int_mock0") 
        self.genericDelTest(host, interface, controller.ModelController.delInterfaceSYNC)

    def testDeleteModelObjectRemovesChildFromParentASYNC(self): 
        host = Host('coco')
        interface = Interface("int_mock0") 
        self.genericDelTest(host, interface, controller.ModelController.delInterfaceASYNC, process_pending=True)

    def testInterfaceFromHostRemovedSYNC(self):
        host = Host('coco')
        interface = Interface("int_mock0") 
        self.genericDelTest(host, interface,
                controller.ModelController.delInterfaceSYNC)

    def testInterfaceFromHostRemovedSYNC(self):
        service = Service('coco')
        interface = Interface("int_mock0") 
        interface.addChild(service)
        self.genericDelTest(interface, service,
                controller.ModelController.delServiceFromInterfaceSYNC)

    def testInterfaceFromHostRemovedASYNC(self):
        service = Service('coco')
        interface = Interface("int_mock0") 
        interface.addChild(service)
        self.genericDelTest(interface, service,
                controller.ModelController.delServiceFromInterfaceASYNC, process_pending=True)

    def testDelVulnFromHostSYNC(self):
        host = Host('coco')
        vuln = ModelObjectVuln("int_mock0") 
        host.addChild(vuln)
        self.genericDelTest(host, vuln,
                controller.ModelController.delVulnFromHostSYNC)

    def testDelVulnFromHostASYNC(self):
        host = Host('coco')
        vuln = ModelObjectVuln("int_mock0") 
        host.addChild(vuln)
        self.genericDelTest(host, vuln,
                controller.ModelController.delVulnFromHostASYNC, process_pending=True)

    def testDelVulnFromObjectSYNC(self):
        host = Host('coco')
        vuln = ModelObjectVuln("int_mock0") 
        host.addChild(vuln)
        self.genericDelTest(host, vuln,
                controller.ModelController.delVulnSYNC)

    def testDelVulnFromServiceSYNC(self):
        service = Service('coco')
        vuln = ModelObjectVuln("int_mock0") 
        service.addChild(vuln)
        self.genericDelTest(service, vuln, 
                controller.ModelController.delVulnFromServiceSYNC)

    def testDelVulnFromServiceASYNC(self):
        service = Service('coco')
        vuln = ModelObjectVuln("int_mock0") 
        service.addChild(vuln)
        self.genericDelTest(service, vuln, 
                controller.ModelController.delVulnFromServiceASYNC, process_pending=True)

    # def delNoteFromInterfaceSYNC(self, hostname, intname, noteId):

    def testDelNoteFromInterfaceSYNC(self):
        interface = Interface('coco')
        note = ModelObjectNote("int_mock0") 
        interface.addChild(note)
        self.genericDelTest(interface, note, 
                controller.ModelController.delNoteFromInterfaceSYNC)

    def testDelNoteFromInterfaceASYNC(self):
        interface = Interface('coco')
        note = ModelObjectNote("int_mock0") 
        interface.addChild(note)
        self.genericDelTest(interface, note, 
                controller.ModelController.delNoteFromInterfaceASYNC, process_pending=True)


    def testDelNoteFromServiceSYNC(self):
        service = Service('coco')
        note = ModelObjectNote("int_mock0") 
        service.addChild(note)
        self.genericDelTest(service, note, 
                controller.ModelController.delNoteFromServiceSYNC)

    def testDelNoteFromServiceASYNC(self):
        service = Service('coco')
        note = ModelObjectNote("int_mock0") 
        service.addChild(note)
        self.genericDelTest(service, note, 
                controller.ModelController.delNoteFromServiceASYNC, process_pending=True)

    def testDelNoteFromHostSYNC(self):
        host = Host('coco')
        note = ModelObjectNote("int_mock0") 
        host.addChild(note)
        self.genericDelTest(host, note, 
                controller.ModelController.delNoteFromHostSYNC)

    def testDelNoteFromHostSYNC(self):
        host = Host('coco')
        note = ModelObjectNote("int_mock0") 
        host.addChild(note)
        self.genericDelTest(host, note, 
                controller.ModelController.delNoteFromHostASYNC, process_pending=True)

    def testDelNoteFromModelObjectSYNC(self):
        host = Host('coco')
        note = ModelObjectNote("int_mock0") 
        host.addChild(note)
        self.genericDelTest(host, note, 
                controller.ModelController.delNoteSYNC)

    def testDelCredentialFromServiceSYNC(self):
        service = Service('coco')
        cred = ModelObjectCred("int_mock0") 
        service.addChild(cred)
        self.genericDelTest(service, cred, 
                controller.ModelController.delCredFromServiceSYNC)

    def testDelCredentialFromServiceASYNC(self):
        service = Service('coco')
        cred = ModelObjectCred("int_mock0") 
        service.addChild(cred)
        self.genericDelTest(service, cred, 
                controller.ModelController.delCredFromServiceASYNC, process_pending=True)

    def testDelCredentialFromModelObjectSYNC(self):
        service = Service('coco')
        cred = ModelObjectCred("int_mock0") 
        service.addChild(cred)
        self.genericDelTest(service, cred, 
                controller.ModelController.delCredSYNC)

    def testDelRemovesObjectFromTrie(self): 
        host = Host("coquito")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        triemock = mock()
        when(mappersManager).getMapper(host.class_signature).thenReturn(objectMapper)
        when(mappersManager).find(host.getID()).thenReturn(host)
        when(triemock).addWord(host.getName()).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager) 
        model_controller.treeWordsTries = triemock
        model_controller.delHostSYNC(host.getID()) 
        verify(mappersManager).remove(host.getID())

        verify(triemock).removeWord(host.getName()) 

    def genericDelTest(self, obj1, obj2, test_method, process_pending=False): 
        mappersManager = self.createMapperMock() 
        objectMapper = mock()
        triemock = mock()
        when(mappersManager).find(obj2.getID()).thenReturn(obj2)
        when(objectMapper).delObject(obj2.getID()).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager) 
        model_controller.treeWordsTries = triemock

        try:
            test_method(model_controller, None, obj2.getID())
        except:
            test_method(model_controller, None, None, obj2.getID())

        if process_pending: 
            model_controller.processAllPendingActions()

        verify(mappersManager).find(obj2.getID())
        verify(mappersManager).remove(obj2.getID())

    def testEditHostSyncGetsMapperDispatchedSYNC(self):
        host = Host("coquito")

        mappersManager = self.createMapperMock()
        dataMapper = mock()
        objectMapper = mock()
        triemock = mock()
        when(mappersManager).getMapper(host.class_signature).thenReturn(dataMapper)
        when(dataMapper).save(host).thenReturn(True)

        model_controller = controller.ModelController(mock(), mappersManager) 

        model_controller.editHostSYNC(host, 'new_name', 'new_desc', 'new_os', True)

        verify(dataMapper).save(host) 

        self.assertEquals(host.getName(), 'new_name', "Name not updated")
        self.assertEquals(host.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(host.getOS(), 'new_os', "OS not updated")
        self.assertEquals(host.isOwned(), True, "Owned status not updated")

    def testEditServiceSyncGetsMapperDispatchedSYNC(self):
        service = Service("coquito")

        params = ('new_name', 'new_desc', 'upd', 9000, 'closed', '2.1', True)
        self.genericEdit(service, params, controller.ModelController.editServiceSYNC)

        self.assertEquals(service.getName(), 'new_name', "Name not updated")
        self.assertEquals(service.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(service.getProtocol(), 'upd', "Protocol not updated")
        self.assertEquals(service.isOwned(), True, "Owned status not updated")

    def testEditServiceSyncGetsMapperDispatchedASYNC(self):
        service = Service("coquito")

        params = ('new_name', 'new_desc', 'upd', 9000, 'closed', '2.1', True)
        self.genericEdit(service, params, controller.ModelController.editServiceASYNC,
                            process_pending=True)

        self.assertEquals(service.getName(), 'new_name', "Name not updated")
        self.assertEquals(service.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(service.getProtocol(), 'upd', "Protocol not updated")
        self.assertEquals(service.isOwned(), True, "Owned status not updated")

    def testEditServiceSyncGetsMapperDispatchedSYNC(self):
        service = Service("coquito")

        params = ('new_name', 'new_desc', 'upd', 9000, 'closed', '2.1', True)
        self.genericEdit(service, params, controller.ModelController.editServiceSYNC)

        self.assertEquals(service.getName(), 'new_name', "Name not updated")
        self.assertEquals(service.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(service.getProtocol(), 'upd', "Protocol not updated")
        self.assertEquals(service.isOwned(), True, "Owned status not updated")

    def testEditServiceSyncGetsMapperDispatchedASYNC(self):
        service = Service("coquito")

        params = ('new_name', 'new_desc', 'upd', 9000, 'closed', '2.1', True)
        self.genericEdit(service, params, controller.ModelController.editServiceASYNC, process_pending=True)

        self.assertEquals(service.getName(), 'new_name', "Name not updated")
        self.assertEquals(service.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(service.getProtocol(), 'upd', "Protocol not updated")
        self.assertEquals(service.isOwned(), True, "Owned status not updated")

    def testEditInterfaceSyncGetsMapperDispatchedSYNC(self):
        inter = Interface("coquito")

        params = ('new_name', 'new_desc', 'hostname1', "FF:AA:EE:11:00", None,
                        None, None, None, None, None, True)

        self.genericEdit(inter, params, controller.ModelController.editInterfaceSYNC)

        self.assertEquals(inter.getName(), 'new_name', "Name not updated")
        self.assertEquals(inter.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(inter.isOwned(), True, "Owned status not updated")


    def testEditVulnSyncGetsMapperDispatchedSYNC(self):
        vuln = ModelObjectVuln("coquito")

        params = ('new_name', 'new_desc', 'high', "ref1")

        self.genericEdit(vuln, params, controller.ModelController.editVulnSYNC)

        self.assertEquals(vuln.getName(), 'new_name', "Name not updated")
        self.assertEquals(vuln.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(vuln.getSeverity(), 'high', "Severity not updated")

    def testEditVulnSyncGetsMapperDispatchedASYNC(self):
        vuln = ModelObjectVuln("coquito")

        params = ('new_name', 'new_desc', 'high', "ref1")

        self.genericEdit(vuln, params, controller.ModelController.editVulnASYNC, process_pending=True)

        self.assertEquals(vuln.getName(), 'new_name', "Name not updated")
        self.assertEquals(vuln.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(vuln.getSeverity(), 'high', "Severity not updated")

    def testEditVulnWebSyncGetsMapperDispatchedSYNC(self):
        vuln = ModelObjectVulnWeb("coquito")

        params = ('new_name', 'new_desc', 'www.goole.com', 'index.html',
                "ref1", 'high', None, None, 'GET', 'pepe', 'coco' , 'caca',
                None)

        self.genericEdit(vuln, params, controller.ModelController.editVulnWebSYNC)

        self.assertEquals(vuln.getName(), 'new_name', "Name not updated")
        self.assertEquals(vuln.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(vuln.getSeverity(), 'high', "Severity not updated")

    def testEditVulnWebSyncGetsMapperDispatchedASYNC(self):
        vuln = ModelObjectVulnWeb("coquito")

        params = ('new_name', 'new_desc', 'www.goole.com', 'index.html',
                "ref1", 'high', None, None, 'GET', 'pepe', 'coco' , 'caca',
                None)

        self.genericEdit(vuln, params, controller.ModelController.editVulnWebASYNC, process_pending=True)

        self.assertEquals(vuln.getName(), 'new_name', "Name not updated")
        self.assertEquals(vuln.getDescription(), 'new_desc', "Description not updated")
        self.assertEquals(vuln.getSeverity(), 'high', "Severity not updated")

    def testEditNoteSyncGetsMapperDispatchedSYNC(self):
        note = ModelObjectNote("coquito")

        params = ('new_name', 'new_desc') 
        self.genericEdit(note, params, controller.ModelController.editNoteSYNC) 
        self.assertEquals(note.getName(), 'new_name', "Name not updated")
        self.assertEquals(note.text, 'new_desc', "Description not updated")

    def testEditNoteSyncGetsMapperDispatchedASYNC(self):
        note = ModelObjectNote("coquito")

        params = ('new_name', 'new_desc') 
        self.genericEdit(note, params, controller.ModelController.editNoteASYNC, process_pending=True) 
        self.assertEquals(note.getName(), 'new_name', "Name not updated")
        self.assertEquals(note.text, 'new_desc', "Description not updated")

    def testEditCredSyncGetsMapperDispatchedSYNC(self):
        cred = ModelObjectCred("coquito")

        params = ('new_user', 'new_pass') 
        self.genericEdit(cred, params, controller.ModelController.editCredSYNC) 
        self.assertEquals(cred.getUsername(), 'new_user', "Username not updated")
        self.assertEquals(cred.getPassword(), 'new_pass', "Password not updated")

    def testEditCredSyncGetsMapperDispatchedASYNC(self):
        cred = ModelObjectCred("coquito")

        params = ('new_user', 'new_pass') 
        self.genericEdit(cred, params, controller.ModelController.editCredASYNC, process_pending=True) 
        self.assertEquals(cred.getUsername(), 'new_user', "Username not updated")
        self.assertEquals(cred.getPassword(), 'new_pass', "Password not updated")

    def testGetAllHosts(self):
        hosts = [ Host("coquito%i" % i ) for i in range(10)]

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(Host.__name__).thenReturn(objectMapper)
        when(objectMapper).getAll().thenReturn(hosts)

        model_controller = controller.ModelController(mock(), mappersManager) 
        hosts_obt =  model_controller.getAllHosts()
        verify(objectMapper).getAll()
        verify(mappersManager).getMapper(Host.__name__)

        self.assertListEqual(hosts, hosts_obt)

    def testGetHost(self):
        host = Host("coquito")

        mappersManager = self.createMapperMock()
        objectMapper = mock()
        when(mappersManager).getMapper(host.__class__.__name__).thenReturn(objectMapper)
        when(objectMapper).find(host.getName()).thenReturn(host)

        model_controller = controller.ModelController(mock(), mappersManager) 

        host_obt =  model_controller.getHost('coquito')

        verify(objectMapper).find(host.getName())
        verify(mappersManager).getMapper(host.__class__.__name__)

        self.assertEqual(host, host_obt)

    def genericEdit(self, obj, params, callback, process_pending=False): 
        mappersManager = self.createMapperMock()
        dataMapper = mock()
        objId = obj.getID()
        when(mappersManager).getMapper(obj.class_signature).thenReturn(dataMapper)
        when(dataMapper).save(obj).thenReturn(True)
        when(mappersManager).find(objId).thenReturn(obj)
        when(mappersManager).save(obj).thenReturn(True) 
        model_controller = controller.ModelController(mock(), mappersManager) 
        callback(model_controller, obj, *params) 
        if process_pending:
            model_controller.processAllPendingActions()


if __name__ == '__main__':
    unittest.main() 

