#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
import os
sys.path.append(os.path.abspath(os.getcwd()))
import random

from mockito import mock, when
import model.guiapi
import time
from model import api
from gui.notifier import NotificationCenter
import plugins.core as plcore
import model.controller as controller
from persistence.change import ChangeModelObject, ChangeCmd, Change

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


def new_random_workspace_name():
    return ("aworkspace" + "".join(random.sample(
        [chr(i) for i in range(65, 90)], 10))).lower()


class ChangesTestSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model_controller = mock(controller.ModelController)
        cls.workspace_manager = mock()
        api.setUpAPIs(cls.model_controller, cls.workspace_manager)
        cls.couch_uri = CONF.getCouchURI()
        # cls.cdm = CouchdbManager(uri=cls.couch_uri)

        class NotificationTest(NotificationCenter):
            def __init__(self, ui):
                self.changes = []

            def changeFromInstance(self, change):
                self.changes.append(change)

        cls.notifier = NotificationTest(None)
        model.guiapi.notification_center = cls.notifier
        cls._couchdb_workspaces = []
        cls.wm = WorkspaceManager(cls.model_controller,
                                  mock(plcore.PluginController))
        cls.workspace = cls.wm.createWorkspace(new_random_workspace_name(),
                                               workspaceClass=WorkspaceOnCouch)
        when(cls.workspace).load().thenReturn(True)
        cls._couchdb_workspaces.append(cls.workspace.name)
        cls.wm.setActiveWorkspace(cls.workspace)

    def setUp(self):
        self.notifier.changes = []

    @classmethod
    def tearDownClass(cls):
        WorkspacePersister.stopThreads()
        # cls.cleanCouchDatabases()

    # @classmethod
    # def cleanCouchDatabases(cls):
    #     try:
    #         for wname in cls._couchdb_workspaces:
    #             cls.cdm.removeWorkspace(wname)
    #     except Exception as e:
    #         print(e)

    def test_model_objects_added(self):
        d1 = {
            'type': 'Service'
        }
        d2 = {
            'type': 'Host'
        }
        d3 = {
            'type': 'Interface'
        }
        self.cdm._getDb(self.workspace.name).save_doc(d1, use_uuids=True,
                                                      force_update=True)
        self.cdm._getDb(self.workspace.name).save_doc(d2, use_uuids=True,
                                                      force_update=True)
        self.cdm._getDb(self.workspace.name).save_doc(d3, use_uuids=True,
                                                      force_update=True)

        time.sleep(1)

        self.assertEquals(len(self.notifier.changes), 3,
                          "Some changes weren't added")
        for change in self.notifier.changes:
            self.assertIsInstance(change, ChangeModelObject,
                                  "It should be a ChangeModelObject")
            self.assertNotIsInstance(change, ChangeCmd,
                                     "It shouldn't be a ChangeCmd")
            self.assertEquals(change.getAction(), Change.MODEL_OBJECT_ADDED,
                              "Change should be an addition")

    def test_model_objects_delete(self):
        d1 = {
            '_id': '1',
            'type': 'Host',
        }
        self.cdm._getDb(self.workspace.name).save_doc(d1, use_uuids=True,
                                                      force_update=True)

        time.sleep(1)

        self.assertEquals(len(self.notifier.changes), 1,
                          "Some changes weren't added")

        self.assertEquals(self.notifier.changes[0].getAction(),
                          Change.MODEL_OBJECT_ADDED,
                          "First change should be an addition")

        self.cdm._getDb(self.workspace.name).delete_doc(d1['_id'])
        time.sleep(1)

        self.assertEquals(self.notifier.changes[1].getAction(),
                          Change.MODEL_OBJECT_DELETED,
                          "Second change should be a Removal")

    def test_model_objects_modified(self):
        d1 = {
            '_id': '1',
            'type': 'Host',
        }
        self.cdm._getDb(self.workspace.name).save_doc(d1, use_uuids=True,
                                                      force_update=True)
        d1 = {
            '_id': '1',
            'type': 'Host',
            'foo': 'bar'
        }
        self.cdm._getDb(self.workspace.name).save_doc(d1, use_uuids=True,
                                                      force_update=True)

        time.sleep(1)

        self.assertEquals(len(self.notifier.changes), 2,
                          "Some changes weren't added")
        self.assertEquals(self.notifier.changes[0].getAction(),
                          Change.MODEL_OBJECT_ADDED,
                          "First change should be an addition")
        self.assertEquals(self.notifier.changes[1].getAction(),
                          Change.MODEL_OBJECT_MODIFIED,
                          "Second change should be a modification")

    def test_cmd_executed(self):
        d1 = {
            'command': 'nmap',
            'params': '-A -T4 127.0.0.1',
            'type': 'CommandRunInformation',
        }
        self.cdm._getDb(self.workspace.name).save_doc(d1, use_uuids=True,
                                                      force_update=True)

        time.sleep(1)

        self.assertEquals(len(self.notifier.changes), 1,
                          "The change wasn't added")
        change = self.notifier.changes[0]
        self.assertNotIsInstance(change, ChangeModelObject,
                                 "It shouldn't be a ChangeModelObject")
        self.assertIsInstance(change, ChangeCmd,
                              "It should be a ChangeCmd")
        self.assertEquals(change.getAction(), Change.CMD_EXECUTED,
                          "Change should be an executed command")

    def test_cmd_finished(self):
        d1 = {
            'command': 'nmap',
            'params': '-A -T4 127.0.0.1',
            'type': 'CommandRunInformation',
        }
        self.cdm._getDb(self.workspace.name).save_doc(d1, use_uuids=True,
                                                      force_update=True)
        d2 = {
            'command': 'nmap',
            'params': '-A -T4 127.0.0.1',
            'type': 'CommandRunInformation',
            'duration': '5'
        }
        self.cdm._getDb(self.workspace.name).save_doc(d2, use_uuids=True,
                                                      force_update=True)

        time.sleep(1)

        self.assertEquals(len(self.notifier.changes), 2,
                          "Some changes weren't added")
        change = self.notifier.changes[1]
        self.assertNotIsInstance(change, ChangeModelObject,
                                 "It shouldn't be a ChangeModelObject")
        self.assertIsInstance(change, ChangeCmd,
                              "It should be a ChangeCmd")
        self.assertEquals(change.getAction(), Change.CMD_FINISHED,
                          "Change should be a finished command")

if __name__ == '__main__':
    unittest.main()
