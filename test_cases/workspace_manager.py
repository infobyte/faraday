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
from model.workspace import Workspace
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

    def testCreateWorkspaceCreateMappersAndWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()

        when(mappersManager).saveObj(any()).thenReturn(True) 
        when(dbManager).dbCreate('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager)
        workspace = workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(mappersManager).createMappers(dbConnector)
        verify(mappersManager).saveObj(any())

        self.assertTrue(workspace, 'workspace not instantiated')
        self.assertEquals(workspace.name, 'test_workspace',
                            'Workspace name not set, is it valid?')

    def testCreateExistingWorkspaceReturnsFalse(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()

        when(mappersManager).saveObj(any()).thenReturn(True) 
        when(dbManager).dbCreate('test_workspace', DBTYPE.FS).thenReturn(False)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager)
        workspace = workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(dbManager).dbCreate('test_workspace', DBTYPE.FS)
        verify(mappersManager, times=0).createMappers(dbConnector)
        verify(mappersManager, times=0).saveObj(any())

    def testOpenWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).dbOpen('test_workspace').thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True)
        when(mappersManager).findObject('test_workspace').thenReturn(workspace)

        workspace_manager = WorkspaceManager(dbManager, mappersManager)

        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(dbManager).dbOpen('test_workspace')
        verify(mappersManager).createMappers(dbConnector)
        verify(mappersManager).findObject('test_workspace')
        self.assertEquals(opened_workspace.getName(), 'test_workspace')

    def testOpenWorkspaceNoneExisting(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()

        workspace = Workspace('test_workspace', 'a desc') 
        when(dbManager).dbOpen('test_workspace').thenReturn(False)

        workspace_manager = WorkspaceManager(dbManager, mappersManager)
        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(dbManager).dbOpen('test_workspace')

        verify(mappersManager, times=0).createMappers(dbConnector)
        verify(mappersManager, times=0).findObject('test_workspace')
        self.assertFalse(opened_workspace, 'Workspace retrieved but non existing')


    def testRemoveWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).dbOpen('test_workspace').thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 
        when(mappersManager).findObject('test_workspace').thenReturn(workspace)

        workspace_manager = WorkspaceManager(dbManager, mappersManager)

        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(dbManager).dbOpen('test_workspace')
        verify(mappersManager).createMappers(dbConnector)
        verify(mappersManager).findObject('test_workspace')
        self.assertEquals(opened_workspace.getName(), 'test_workspace')


if __name__ == '__main__':
    unittest.main()

