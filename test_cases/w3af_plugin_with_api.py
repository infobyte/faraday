'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
import os
sys.path.append('.')
import model.controller as controller
from model.workspace import Workspace
from model.container import ModelObjectContainer
import model.api as api
#from model import controller
#from model import api
from plugins.repo.w3af import plugin
from plugins.core import PluginControllerForApi
from mockito import mock, when
from managers.all import CommandManager


class W3afPluginTest(unittest.TestCase):

    def setUp(self):
        """
        Generic test to verify that the object exists and can be
        instantiated without problems.
        """
        self.model_controller = controller.ModelController(mock())
        self.workspace = mock(Workspace)
        when(self.workspace).getContainee().thenReturn(ModelObjectContainer())
        self.cm = mock(CommandManager)
        when(self.cm).saveCommand().thenReturn(True)
        self.model_controller.setWorkspace(self.workspace)
        self._plugin_controller = PluginControllerForApi("test", {"w3af": plugin.W3afPlugin()}, self.cm)
        api.setUpAPIs(self.model_controller)

    def test_report(self):
        output_file = open(os.path.join(os.getcwd(), 'test_cases/data/w3af_plugin_with_api.xml'))
        output = output_file.read() 
        self._plugin_controller.processCommandInput("./w3af report")
        self._plugin_controller.onCommandFinished("./w3af report", output)
        self.model_controller.processAllPendingActions()
        self.assertEquals(len(self.model_controller.getAllHosts()), 1,
                "Not all hosts added to model")


if __name__ == '__main__':
    unittest.main()
