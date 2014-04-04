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
# from plugins import core
# from plugins import managers
import re

from model.commands_history import CommandRunInformation
from model.controller import ModelController
from plugins.core import PluginController

from model.workspace import WorkspaceOnCouch, WorkspaceManager
from mockito import mock

from time import time

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

from managers.all import CommandManager, CouchdbManager, PersistenceManagerFactory

class CommandHistoryTestSuite(unittest.TestCase):

    def setUp(self):
        pass
        # self.couch_host = "http://192.168.33.101:5984"
        # CONF.setCouchUri(self.couch_host)

    def test_valid_command_creation(self):
        information = self.getDefaultCommandInfo()

        command_info = CommandRunInformation(**information)
        self.assertIsNotNone(command_info, "Command wrongly created")

        self.assertEquals(command_info.command, information['command'], \
                "Field %s not instantiated" % information['command'])

        self.assertEquals(command_info.parameters, information['parameters'], \
                "Field %s not instantiated" % information['parameters'])

        self.assertEquals(command_info.itime, information['itime'], \
                "Field %s not instantiated" % information['itime'])

        self.assertEquals(command_info.duration, information['duration'], \
                "Field %s not instantiated" % information['duration'])

        self.assertEquals(command_info.workspace, information['workspace'], \
                "Field %s not instantiated" % information['workspace'])

    def test_create_command_manager(self):
        """ Tests the command manager creation """
        cm = CommandManager()
        self.assertIsNotNone(cm, "Command Manager not instantiated")

    def test_save_command_in_couch(self):
        """ Tests if command is saved in couch """
        cm = CommandManager()

        exec_command = CommandRunInformation(**self.getDefaultCommandInfo())

        wm = WorkspaceManager(mock(ModelController), mock(PluginController))
        c = wm.createWorkspace(exec_command.workspace, workspaceClass=WorkspaceOnCouch)

        res = cm.saveCommand(exec_command)

        self._manager = PersistenceManagerFactory.getInstance()
        saved_doc = self._manager.getDocument(exec_command.workspace, res['id'] )

        self.assertEquals(exec_command.command, saved_doc['command'], 'Saved command diffier')
        self.assertEquals(exec_command.parameters, saved_doc['parameters'], 'Saved command diffier')
        self.assertEquals(exec_command.itime, saved_doc['itime'], 'Saved command diffier')
        self.assertEquals(exec_command.duration, saved_doc['duration'], 'Saved command diffier')


    def getDefaultCommandInfo(self):
        information = { 'command' : 'nmap',
                        'parameters' : '-Sv',
                        'itime' : time(),
                        'duration' : 5,
                        'workspace' : 'default'
                        }

        return information


if __name__ == '__main__':
    unittest.main()

