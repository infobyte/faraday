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
from time import time


class CommandHistoryTestSuite(unittest.TestCase):

    def setUp(self):
        # self.plugin_repo_path = os.path.join(os.getcwd(), "plugins", "repo")
        # self.plugin_manager = managers.PluginManager(self.plugin_repo_path)
        pass

        # class WorkspaceStub():
        #     def __init__(self):
        #         self.id = "test_space"
        # self.controller = \
        #     self.plugin_manager.createController(WorkspaceStub())

    def test_valid_command_creation(self):
        information = { 'command' : 'nmap',
                        'parameters' : '-Sv',
                        'itime' : time(),
                        'duration' : 5,
                        'workspace' : 'default'
                        }


        command_info = CommandRunInformation(**information)
        self.assertIsNotNone(command_info, "Command wrongly created")

        self.assertEquals(command_info.command, information['command'], "Field
                %s not instantiated" % information['command'])

        self.assertEquals(command_info.parameters, information['parameters'],
                "Field %s not instantiated" % information['parameters'])

        self.assertEquals(command_info.itime, information['itime'], "Field %s
                not instantiated" % information['itime'])

        self.assertEquals(command_info.duration, information['duration'],
                "Field %s not instantiated" % information['duration'])

        self.assertEquals(command_info.workspace, information['workspace'],
                "Field %s not instantiated" % information['workspace'])


if __name__ == '__main__':
    unittest.main()

