#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
sys.path.append('.')

from config.configuration import getInstanceConfiguration
from managers.model_managers import WorkspaceManager
from persistence.persistence_managers import DBTYPE
from mockito import mock, verify, when, any
CONF = getInstanceConfiguration()

class UnitTestWorkspaceManager(unittest.TestCase):
    """ Unit tests for WorkspaceManager """

    def testCreateWorkspaceManager(self):
        workspace_manager = WorkspaceManager(mock(), mock())
        self.assertIsNotNone(workspace_manager)

    def testCreateWorkspaceDBManagerInteract(self):
        dbManager = mock()
        dbConnector = mock()
        when(dbManager).dbCreate('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        workspace_manager = WorkspaceManager(dbManager, mock())
        workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)
        verify(dbManager).dbCreate('test_workspace', DBTYPE.FS)

    def testCreateWorkspaceReturnsWorkspace(self):
        workspace_manager = WorkspaceManager(mock(), mock())
        workspace = workspace_manager.createWorkspace('test_workspace', 
                                        'a test workspace',
                                        DBTYPE.FS)
        self.assertTrue(workspace, 'workspace not instantiated')
        self.assertEquals(workspace.name, 'test_workspace',
                            'Workspace name not set, is it valid?')

    def testCreateWorkspaceCreateMappers(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()

        when(mappersManager).saveObj(any()).thenReturn(True) 
        when(dbManager).dbCreate('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager)
        workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(mappersManager).createMappers(dbConnector)
        verify(mappersManager).saveObj(any())



if __name__ == '__main__':
    unittest.main()
