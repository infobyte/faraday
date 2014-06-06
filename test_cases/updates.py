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
from model.workspace import WorkspaceOnCouch, WorkspaceManager
from persistence.orm import WorkspacePersister

import test_cases.common as test_utils


class UpdatesTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model_controller = controller.ModelController(mock())
        api.setUpAPIs(cls.model_controller)
        cls.wm = WorkspaceManager(cls.model_controller,
                                  mock(plcore.PluginController))
        cls.temp_workspace = cls.wm.createWorkspace(
            test_utils.new_random_workspace_name(),
            workspaceClass=WorkspaceOnCouch)

        cls.wm.setActiveWorkspace(cls.temp_workspace)
        WorkspacePersister.stopThreads()

    def setUp(self):
        pass

    @classmethod
    def tearDownClass(cls):
        WorkspacePersister.stopThreads()
        cls.wm.removeWorkspace(cls.temp_workspace.name)

    def tearDown(self):
        pass

    def testAddHost(self):
        """ This test case creates a host within the Model Controller context
        then checks it's vality"""
        # When
        hostname = 'host'
        test_utils.create_host(self, host_name=hostname, os='windows')
        # Then, we generate an update
        test_utils.create_host(self, host_name=hostname, os='linux')

        self.assertEquals(len(self.model_controller.getConflicts()), 1,
                          'Update not generated')

        conflict = self.model_controller.getConflicts()[0]


if __name__ == '__main__':
    unittest.main()
