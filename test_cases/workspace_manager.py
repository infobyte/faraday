#!/usr/bin/python
'''
Faraday Penetration Test IDE
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
        workspace_manager = WorkspaceManager(mock(), mock(), mock(), mock())
        self.assertIsNotNone(workspace_manager)

    def testOpenWorkspaceChangesAndReportManagerWatch(self):
        reportManager = mock()

        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()
        workspaceMapper = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).getAllDbNames().thenReturn(['test_workspace'])
        when(dbManager).getConnector('test_workspace').thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True)
        when(mappersManager).getMapper(Workspace.__name__).thenReturn(workspaceMapper)
        when(workspaceMapper).find('test_workspace').thenReturn(workspace)

        workspace_manager = WorkspaceManager(dbManager,
                                mappersManager,
                                changesController,
                                reportManager)


        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(reportManager).watch('test_workspace')
        verify(changesController).watch(mappersManager, dbConnector)
        self.assertEquals(opened_workspace.getName(), 'test_workspace')


    def testCreateWorkspaceDBManagerInteract(self):
        dbManager = mock()
        dbConnector = mock()
        changesController = mock()

        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        workspace_manager = WorkspaceManager(dbManager, mock(), changesController, mock())
        workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)
        verify(dbManager).createDb('test_workspace', DBTYPE.FS)

    def testCreateWorkspaceCreateMappersAndWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()
        workspaceMapper = mock()

        when(mappersManager).getMapper(Workspace.__name__).thenReturn(workspaceMapper)
        when(mappersManager).save(any()).thenReturn(True) 
        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())
        workspace = workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(mappersManager).createMappers(dbConnector)
        verify(mappersManager).save(any())

        self.assertTrue(workspace, 'workspace not instantiated')
        self.assertEquals(workspace.name, 'test_workspace',
                            'Workspace name not set, is it valid?')

    def testCreateExistingWorkspaceReturnsFalse(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()

        when(mappersManager).save(any()).thenReturn(True) 
        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(False)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())
        workspace = workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(dbManager).createDb('test_workspace', DBTYPE.FS)
        verify(mappersManager, times=0).createMappers(dbConnector)
        verify(mappersManager, times=0).save(any())

    def testOpenWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()
        workspaceMapper = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).getConnector('test_workspace').thenReturn(dbConnector)
        when(mappersManager).getMapper(Workspace.__name__).thenReturn(workspaceMapper)
        when(dbManager).getAllDbNames().thenReturn(['test_workspace'])
        when(mappersManager).createMappers(dbConnector).thenReturn(True)
        when(workspaceMapper).find('test_workspace').thenReturn(workspace)

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())

        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(dbManager).getConnector('test_workspace')
        verify(mappersManager).createMappers(dbConnector)
        verify(workspaceMapper).find('test_workspace')
        self.assertEquals(opened_workspace.getName(), 'test_workspace')

    def testOpenWorkspaceSetsChangesCallback(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()
        workspaceMapper = mock()

        workspace = Workspace('test_workspace', 'a desc')

        when(dbManager).getConnector('test_workspace').thenReturn(dbConnector)
        when(mappersManager).getMapper(Workspace.__name__).thenReturn(workspaceMapper)
        when(dbManager).getAllDbNames().thenReturn(['test_workspace'])
        when(mappersManager).createMappers(dbConnector).thenReturn(True)
        when(workspaceMapper).find('test_workspace').thenReturn(workspace)

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())

        opened_workspace = workspace_manager.openWorkspace('test_workspace')

        verify(changesController).watch(mappersManager, dbConnector)

    def testCreateWorkspaceSetsChangesCallback(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()

        when(mappersManager).save(any()).thenReturn(True) 
        when(dbManager).createDb('test_workspace', DBTYPE.FS).thenReturn(dbConnector)
        when(mappersManager).createMappers(dbConnector).thenReturn(True) 

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())
        workspace = workspace_manager.createWorkspace('test_workspace', 'a test workspace',
                                        DBTYPE.FS)

        verify(changesController).watch(mappersManager, dbConnector)

    def testOpenWorkspaceNoneExisting(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()

        workspace = Workspace('test_workspace', 'a desc') 
        when(dbManager).getAllDbNames().thenReturn([])

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())
        opened_workspace = workspace_manager.openWorkspace('test_workspace')


        verify(mappersManager, times=0).createMappers(dbConnector)
        verify(mappersManager, times=0).find('test_workspace')
        self.assertFalse(opened_workspace, 'Workspace retrieved but non existing')

    def testRemoveWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        dbConnector = mock()
        mappers = mock()
        changesController = mock()

        workspace = Workspace('test_workspace', 'a desc')
        when(dbManager).removeDb('test_workspace').thenReturn(True)
        when(dbManager).getAllDbNames().thenReturn(['test_workspace'])

        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())
        remove_ret = workspace_manager.removeWorkspace('test_workspace')

        verify(dbManager).removeDb('test_workspace')
        self.assertTrue(remove_ret, 'bbdd not removed')

    def testSetActiveWorkspace(self):
        work = Workspace('testname')
        dbManager = mock()
        mappersManager = mock()
        changesController = mock()
        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())

        workspace_manager.setActiveWorkspace(work)

        self.assertEquals(workspace_manager.active_workspace, work,
                'active workspace not set')
        self.assertTrue(workspace_manager.isActive(work.getName()),
                'could not retrive as active workspace')

    def testGetWorkspaceTypeCouchDb(self):
        work = Workspace('testname')
        dbManager = mock()
        mappersManager = mock()
        changesController = mock()
        when(dbManager).getDbType('testname').thenReturn(DBTYPE.COUCHDB)
        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())

        wtype = workspace_manager.getWorkspaceType(work.getName())
        self.assertEquals(wtype, 'CouchDB', 'Workspace type not returning correct value')

    def testGetWorkspaceTypeFS(self):
        work = Workspace('testname')
        dbManager = mock()
        mappersManager = mock()
        changesController = mock()
        when(dbManager).getDbType('testname').thenReturn(DBTYPE.FS)
        workspace_manager = WorkspaceManager(dbManager, mappersManager, changesController, mock())

        wtype = workspace_manager.getWorkspaceType(work.getName())
        self.assertEquals(wtype, 'FS', 'Workspace type not returning correct value')

    def testGetAvailableWorkspaceTypes(self): 
        dbManager = mock()
        workspace_manager = WorkspaceManager(dbManager,
                                                mock(),
                                                mock(),
                                                mock())
        when(dbManager).getAvailableDBs().thenReturn([DBTYPE.COUCHDB, DBTYPE.FS])
        retrievedTypes = workspace_manager.getAvailableWorkspaceTypes()

        self.assertListEqual(['CouchDB', 'FS'], retrievedTypes, 
                                    "Workspaces available Types not set")

    def testCloseWorkspace(self):
        dbManager = mock()
        mappersManager = mock()
        changesController = mock()
        reportManager = mock()


        workspace_manager = WorkspaceManager(dbManager,
                                                mappersManager,
                                                changesController,
                                                reportManager)

        workspace_manager.closeWorkspace()
        verify(changesController).unwatch()

    def testResourceManager(self):
        dbManager = mock()
        mappersManager = mock()
        changesController = mock()
        reportManager = mock()


        workspace_manager = WorkspaceManager(dbManager,
                                                mappersManager,
                                                changesController,
                                                reportManager)

        workspace_manager.resource()

        verify(dbManager).reloadConfig()




if __name__ == '__main__':
    unittest.main()

