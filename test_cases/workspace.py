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
from model.workspace import CouchdbManager, WorkspaceManager, WorkspaceOnCouch, WorkspaceOnFS
from model.controller import ModelController

from plugins.core import PluginController
import random

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

from mockito import mock


class TestWorkspacesManagement(unittest.TestCase):
    """Used to test how a workspace changes and is updated"""

    def setUp(self):
        self.couch_uri = CONF.getCouchURI()
        self.cdm = CouchdbManager(uri=self.couch_uri)
        self._fs_workspaces = []
        self._couchdb_workspaces = []

    def tearDown(self):
        self.cleanCouchDatabases()
        self.cleanFSWorkspaces()
        # pass

    def new_random_workspace_name(self):
        return ("aworkspace" + "".join(random.sample([chr(i) for i in range(65, 90)], 10))).lower()

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

    def test_create_fs_workspace(self):
        wname = self.new_random_workspace_name()
        self._fs_workspaces.append(wname)
        wm = WorkspaceManager(mock(ModelController), mock(PluginController))
        wm.createWorkspace(wname, workspaceClass=WorkspaceOnFS)

        self.assertFalse(self.cdm.existWorkspace(wname))

        wpath = os.path.expanduser("~/.faraday/persistence/%s" % wname)
        self.assertTrue(os.path.exists(wpath))

    def test_create_couch_workspace(self):
        wname = self.new_random_workspace_name()
        self._couchdb_workspaces.append(wname)
        wm = WorkspaceManager(mock(ModelController), mock(PluginController))
        wm.createWorkspace(wname, workspaceClass=WorkspaceOnCouch)

        self.assertTrue(self.cdm.existWorkspace(wname))

        wpath = os.path.expanduser("~/.faraday/persistence/%s" % wname)
        self.assertFalse(os.path.exists(wpath))

    def test_delete_couch_workspace(self):
        wname = self.new_random_workspace_name()
        wm = WorkspaceManager(mock(ModelController), mock(PluginController))
        wm.createWorkspace(wname, workspaceClass=WorkspaceOnCouch)

        self.assertTrue(self.cdm.existWorkspace(wname))

        #Delete workspace
        wm.removeWorkspace(wname)
        self.assertFalse(self.cdm.existWorkspace(wname))

    def test_delete_fs_workspace(self):
        wname = self.new_random_workspace_name()
        wm = WorkspaceManager(mock(ModelController), mock(PluginController))
        wm.createWorkspace(wname, workspaceClass=WorkspaceOnFS)

        wpath = os.path.expanduser("~/.faraday/persistence/%s" % wname)
        self.assertTrue(os.path.exists(wpath))

        #Delete workspace
        wm.removeWorkspace(wname)
        self.assertFalse(os.path.exists(wpath))


if __name__ == '__main__':
    unittest.main()
