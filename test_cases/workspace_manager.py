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
        workspace_manager = WorkspaceManager(mock(), mock(), mock())
        self.assertIsNotNone(workspace_manager)

    def testCreateWorkspaceDBManagerInteract(self):
        dbManager = mock()
        dbConnector = mock()
        changesManager = mock()

        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        workspace_manager = WorkspaceManager(dbManager, mock(), changesManager)
        workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)
        verify(dbManager).createDb('test_workspace', DBTYPE.FS)

    def testCreateWorkspaceCreateMappersAndWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesManager = mock()

        when(mappersManager).saveObj(any()).thenReturn(True) 
        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)
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
        changesManager = mock()

        when(mappersManager).saveObj(any()).thenReturn(True) 
        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(False)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)
        workspace = workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(dbManager).createDb('test_workspace', DBTYPE.FS)
        verify(mappersManager, times=0).createMappers(dbConnector)
        verify(mappersManager, times=0).saveObj(any())

    def testOpenWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesManager = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).dbOpen('test_workspace').thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True)
        when(mappersManager).find('test_workspace').thenReturn(workspace)

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)

        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(dbManager).dbOpen('test_workspace')
        verify(mappersManager).createMappers(dbConnector)
        verify(mappersManager).find('test_workspace')
        self.assertEquals(opened_workspace.getName(), 'test_workspace')

    def testOpenWorkspaceSetsChangesCallback(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesManager = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).dbOpen('test_workspace').thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True)
        when(mappersManager).find('test_workspace').thenReturn(workspace)

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager) 
        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(dbConnector).setChangesCallback(changesManager)

    def testCreateWorkspaceSetsChangesCallback(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesManager = mock()

        when(mappersManager).saveObj(any()).thenReturn(True) 
        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)
        workspace = workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(dbConnector).setChangesCallback(changesManager)

    def testOpenWorkspaceNoneExisting(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesManager = mock()

        workspace = Workspace('test_workspace', 'a desc') 
        when(dbManager).dbOpen('test_workspace').thenReturn(False)

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)
        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(dbManager).dbOpen('test_workspace')

        verify(mappersManager, times=0).createMappers(dbConnector)
        verify(mappersManager, times=0).find('test_workspace')
        self.assertFalse(opened_workspace, 'Workspace retrieved but non existing')

    def testRemoveWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesManager = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).removeDb('test_workspace').thenReturn(True)

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)
        remove_ret = workspace_manager.removeWorkspace('test_workspace')

        verify(dbManager).removeDb('test_workspace')
        self.assertTrue(remove_ret, 'bbdd not removed')

    def testSetActiveWorkspace(self):
        work = Workspace('testname')
        dbManager = mock()
        mappersManager = mock()
        changesManager = mock()
        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)

        workspace_manager.setActiveWorkspace(work)

        self.assertEquals(workspace_manager.active_workspace, work,
                'active workspace not set')
        self.assertTrue(workspace_manager.isActive(work.getName()),
                'could not retrive as active workspace')

    def testGetWorkspaceTypeCouchDb(self):
        work = Workspace('testname')
        dbManager = mock()
        mappersManager = mock()
        changesManager = mock()
        when(dbManager).getDbType('testname').thenReturn(DBTYPE.COUCHDB)
        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)

        wtype = workspace_manager.getWorkspaceType(work.getName())
        self.assertEquals(wtype, 'CouchDB', 'Workspace type not returning correct value')

    def testGetWorkspaceTypeFS(self):
        work = Workspace('testname')
        dbManager = mock()
        mappersManager = mock()
        changesManager = mock()
        when(dbManager).getDbType('testname').thenReturn(DBTYPE.FS)
        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesManager)

        wtype = workspace_manager.getWorkspaceType(work.getName())
        self.assertEquals(wtype, 'FS', 'Workspace type not returning correct value')


if __name__ == '__main__':
    unittest.main()

