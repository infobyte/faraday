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
from managers.model_managers import WorkspaceManager
from plugins.repo.nmap import plugin
from plugins.core import PluginControllerForApi
from mockito import mock, when, any

from persistence.persistence_managers import DBTYPE

from managers.mapper_manager import MapperManager
from managers.reports_managers import ReportManager
from persistence.persistence_managers import DbManager

class PluginsToModelControllerIntegration(unittest.TestCase):

    def setUp(self):
        """
        Generic test to verify that the object exists and can be
        instantiated without problems.
        """
        self.dbManager = mock()
        self.changesController = mock()
        self.reportManager = mock()

        self.dbManager = DbManager()
        self.mappersManager = MapperManager()

        self.model_controller = controller.ModelController(mock(), self.mappersManager)
        self.workspace_manager = WorkspaceManager(self.dbManager,
                                             self.mappersManager,
                                             self.changesController,
                                             self.reportManager)
        self.workspace_manager.createWorkspace('temp_workspace', 'desc', DBTYPE.FS)
        self.workspace_manager.openWorkspace('temp_workspace')

        self._plugin_controller = PluginControllerForApi("test", {"nmap": plugin.NmapPlugin()}, mock())

        api.setUpAPIs(self.model_controller, self.workspace_manager)

    def tearDown(self): 
        self.workspace_manager.removeWorkspace('temp_workspace')

    def _test_nmap_scan_saves_host(self):
        output_file = open(os.path.join(os.getcwd(), 'test_cases/data/nmap_plugin_with_api.xml'))
        output = output_file.read()
        self._plugin_controller.processCommandInput("nmap localhost")
        self._plugin_controller.onCommandFinished("nmap localhost", output)
        self.model_controller.processAllPendingActions()
        self.assertEquals(len(self.model_controller.getAllHosts()), 1,
                "Not all hosts added to model")

        host = self.model_controller.getAllHosts()[0]
        self.assertEquals(len(host.getAllInterfaces()), 1,
            "Not all interfaces added to model")

        interface = host.getAllInterfaces()[0]
        self.assertEquals(len(interface.getAllServices()), 3,
            "Not all services added to model")

        services = interface.getAllServices()
        self.assertTrue(all( [ s.getStatus() == 'open' for s in services]),
                "Port status not saved correctly")


    def test_nessus_scan_saves_host(self):
        output_file = open(os.path.join(os.getcwd(), 'test_cases/data/nessus_plugin_with_api.nessus'))
        output = output_file.read() 
        self._plugin_controller.processCommandInput("./nessus report")
        self._plugin_controller.onCommandFinished("./nessus report", output)
        self.model_controller.processAllPendingActions()
        self.assertEquals(len(self.model_controller.getAllHosts()), 7,
                "Not all hosts added to model")

if __name__ == '__main__':
    unittest.main()
