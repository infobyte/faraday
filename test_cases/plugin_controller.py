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
from plugins.core import  PluginController
from managers.all import PluginManager
import re

# TODO: Doc strings

__author__     = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__  = "Copyright 2010, Faraday Project"
__credits__    = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__    = "GPL"
__version__    = "1.0.0"
__maintainer__ = "Facundo de Guzmán"
__email__      = "fdeguzman@ribadeohacklab.com.ar"
__status__     = "Development"


class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        self.plugin_repo_path = os.path.join(os.getcwd(), "plugins", "repo")
        self.plugin_manager = PluginManager(self.plugin_repo_path)

        class WorkspaceStub():
            def __init__(self):
                self.id = "test_space"
        self.controller = self.plugin_manager.createController(WorkspaceStub())

    def tearDown(self):
        pass

    def test_instantiation(self):
        """
        Generic test to verify that the object exists and can be
        instantiated without problems.
        """
        controller = PluginController("test", {})
        self.assertTrue(controller is not None)

    def test_sanitation_checker(self):
        """
        The object of this test is to verify that the plugin controller
        is able to detect and avoid malicious commands sent by rogue plugins.
        The mechanism is not intend to be perfect but at least should give some
        amount of protection.
        """
        controller = PluginController("test", {})

        original_command = "nmap -v -iR 10000 -PN -p 80"
        modified_command = "nmap -v -iR 10000 -PN -p 80|"

        self.assertTrue(controller._is_command_malformed(original_command, modified_command), 
                'Modified command is malformed')

        original_command = "nmap -v -iR 10000 -PN -p 80"
        modified_command = "nmap -v -i#R 10000 -PN -p 80"
        self.assertTrue(controller._is_command_malformed(original_command, modified_command), 
                'Modified command is malformed')

        original_command = "nmap -v -iR 10000 -PN -p 80"
        modified_command = "nmap -v -iR $10000 -PN -p 80"
        self.assertTrue(controller._is_command_malformed(original_command, modified_command), 
                'Modified command is malformed')

        original_command = "nmap -v -iR 10000 -PN -p 80"
        modified_command = "nmap -v -iR 10000 -PN -p 80"

        self.assertTrue( not controller._is_command_malformed(original_command, modified_command), 
                    "Original Command same as modified command but is malformed")

    def test_input_processing(self):
        """
        Check that the controller is able to give the active plugin an input and
        verify that what the plugin gives back to it is a safe command string.

        TODO: Fix the docstring. It sucks.
        TODO: Use a generic plugin.
        """

        prompt = "fdeguzman@testserver:$"

        command_string = "nmap localhost"
        modified_string = self.controller.processCommandInput(prompt, "", "", 
                                                         command_string, False)
        arg_search = re.match(r"^.*(-oX\s*[^\s]+).*$", modified_string)
        self.assertTrue(arg_search is not None)

        command_string = "nmap -oX benito_camelas.xml localhost"
        modified_string = self.controller.processCommandInput(prompt, "", "",  command_string, False)
        arg_search = re.match(r"^.*(-oX benito_camelas\.xml).*$", modified_string)
        self.assertTrue(arg_search is None)

    def test_plugin_suggestion(self):
        """
        Test to verify that we can get reliable plugin suggestions after
        we send some command inputs to the plugin controller. This tests
        expects the nmap plugin and the amap plugin to be present in the
        plugin repo.
        """
        prompt = "fdeguzman@testserver:$"

        command_string = "nmap localhost"
        modified_string = self.controller.processCommandInput(prompt, "", "", 
                                                         command_string, False)
        self.controller.onCommandFinished()

    def test_output_parsing(self):
        """
        Test that after receiving an output, the plugin controller gives
        it to the correct plugin to parse it. Expects the nmap plugin and
        the amap plugin to be present in the plugin repo.
        """
        pass



if __name__ == '__main__':
    unittest.main()

