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
from mockito import mock, verify, when
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

    def setUp(self):
        pass

    # def setUp(self):
    #     self.wm = WorkspaceManager(self.model_controller,
    #                                 mock(plcore.PluginController))

    #     self.temp_workspace = self.wm.createWorkspace(
    #                                     test_utils.new_random_workspace_name(),
    #                                     workspaceClass=WorkspaceOnCouch)

    #     self.wm.setActiveWorkspace(self.temp_workspace)
    #     WorkspacePersister.stopThreads()

    # def tearDown(self):
    #     self.wm.removeWorkspace(self.temp_workspace.name)

    def testAddHost(self):

        host = Host('coco')

        mappersManager = mock()
        objectMapper = mock()
        when(mappersManager).getMapper(host).thenReturn(objectMapper)

        model_controller = controller.ModelController(mock(), mappersManager)

        model_controller.addHostSYNC(host)
        verify(mappersManager).getMapper(host)

if __name__ == '__main__':
    unittest.main() 

