#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import unittest
import os
import sys
sys.path.append('.')
from model.workspace import (FSManager, CouchdbManager, WorkspaceManager,
                             WorkspaceOnCouch, WorkspaceOnFS)
from model.controller import ModelController

from plugins.core import PluginController
import random

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

from mockito import mock


class TestWorkspacesManagement(unittest.TestCase):

    def setUp(self):
        self.couch_uri = CONF.getCouchURI()
        self.cdm = CouchdbManager(uri=self.couch_uri)
        wpath = os.path.expanduser("~/.faraday/persistence/" )
        self.fsm = FSManager(wpath)
        self.wm = WorkspaceManager(mock(ModelController),
                                   mock(PluginController))
        self._fs_workspaces = []
        self._couchdb_workspaces = []

    def tearDown(self):
        self.cleanCouchDatabases()
        self.cleanFSWorkspaces()
        # pass

    def new_random_workspace_name(self):
        return ("aworkspace" + "".join(random.sample(
            [chr(i) for i in range(65, 90)], 10))).lower()

    def cleanFSWorkspaces(self):
        import shutil
        basepath = os.path.expanduser("~/.faraday/persistence/")

        for d in self._fs_workspaces:
            wpath = os.path.join(basepath, d)
            if os.path.isdir(wpath):
                shutil.rmtree(wpath)

    def cleanCouchDatabases(self):
        try:
            for wname in self._couchdb_workspaces:
                self.cdm.removeWorkspace(wname)
        except Exception as e:
            print e

    def _test_create_fs_workspace(self):
        """
        Verifies the creation of a filesystem workspace
        """
        wname = self.new_random_workspace_name()
        self._fs_workspaces.append(wname)
        self.wm.createWorkspace(wname, workspaceClass=WorkspaceOnFS)

        self.assertFalse(self.cdm.existWorkspace(wname))

        wpath = os.path.expanduser("~/.faraday/persistence/%s" % wname)
        self.assertTrue(os.path.exists(wpath))

    def _test_create_couch_workspace(self):
        """
        Verifies the creation of a couch workspace
        """
        wname = self.new_random_workspace_name()
        self._couchdb_workspaces.append(wname)
        self.wm.createWorkspace(wname, workspaceClass=WorkspaceOnCouch)

        self.assertTrue(self.cdm.existWorkspace(wname))

        wpath = os.path.expanduser("~/.faraday/persistence/%s" % wname)
        self.assertFalse(os.path.exists(wpath))

    def _test_delete_couch_workspace(self):
        """
        Verifies the deletion of a couch workspace
        """
        wname = self.new_random_workspace_name()
        self.wm.createWorkspace(wname, workspaceClass=WorkspaceOnCouch)

        self.assertTrue(self.cdm.existWorkspace(wname))

        #Delete workspace
        self.wm.removeWorkspace(wname)
        self.assertFalse(self.cdm.existWorkspace(wname))

    def _test_delete_fs_workspace(self):
        """
        Verifies the deletion of a filesystem workspace
        """
        wname = self.new_random_workspace_name()
        self.wm.createWorkspace(wname, workspaceClass=WorkspaceOnFS)

        wpath = os.path.expanduser("~/.faraday/persistence/%s" % wname)
        self.assertTrue(os.path.exists(wpath))

        #Delete workspace
        self.wm.removeWorkspace(wname)
        self.assertFalse(os.path.exists(wpath))

    def test_list_workspaces(self):
        """ Lists FS workspaces and Couch workspaces """
        # First create workspaces manually 
        wnamefs = self.new_random_workspace_name()
        wnamecouch = self.new_random_workspace_name() 
        # FS
        self.fsm.addWorkspace(wnamefs)
        # Couch
        self.cdm.addWorkspace(wnamecouch)

        # When  loading workspaces
        self.wm.loadWorkspaces()

        self.assertIn(wnamefs, self.wm.getWorkspacesNames(), 'FS Workspace not loaded')
        self.assertIn(wnamecouch, self.wm.getWorkspacesNames(), 'Couch Workspace not loaded')


if __name__ == '__main__':
    unittest.main()
