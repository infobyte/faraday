'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import unittest
import os
import requests
import json
import sys
from mockito import mock, when

sys.path.append('.')

from managers.all import PluginManager
import plugins.api
import model.api
import model.controller
from model.workspace import Workspace
from model.container import ModelObjectContainer


class TestPluginControllerApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        plugin_repo_path = os.path.join(os.getcwd(), "plugins", "repo")
        plugin_manager = PluginManager(plugin_repo_path)
        plugins.api.startPluginControllerAPI(plugin_manager)

    @classmethod
    def tearDownClass(cls):
        plugins.api.stopPluginControllerAPI()

    def setUp(self):
        self.model_controller = model.controller.ModelController(mock())
        self.workspace = mock(Workspace)
        self.workspace.name = "default"
        when(self.workspace).getContainee().thenReturn(ModelObjectContainer())
        self.model_controller.setWorkspace(self.workspace)

        model.api.setUpAPIs(self.model_controller)
        self.url_input = "http://127.0.0.1:9977/cmd/input"
        self.url_output = "http://127.0.0.1:9977/cmd/output"
        self.url_active_plugins = "http://127.0.0.1:9977/cmd/active-plugins"
        self.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

    def tearDown(self):
        requests.delete(self.url_active_plugins)

    def test_cmd_input_ls(self):
        cmd = "ls"
        data = {"cmd": cmd}
        response = requests.post(self.url_input,
                                 data=json.dumps(data),
                                 headers=self.headers)

        self.assertEquals(response.status_code, 204, "Status Code should be 204: No Content, but received: %d" % response.status_code)


    def test_cmd_input_ping(self):
        cmd = "ping 127.0.0.1"
        data = {"cmd": cmd}
        response = requests.post(self.url_input,
                                 data=json.dumps(data),
                                 headers=self.headers)
        json_response = response.json()

        self.assertEquals(response.status_code, 200, "Status Code should be 200: OK, but received: %d" % response.status_code)
        self.assertIn("cmd", json_response.keys(), "Json response should have a cmd key")
        self.assertIn("custom_output_file", json_response.keys(), "Json response should have a custom_output_file key")
        self.assertIsNone(json_response.get("cmd"), "cmd should be None")
        self.assertIsNone(json_response.get("custom_output_file"), "custom_output_file should be None")

    def test_cmd_input_nmap(self):
        cmd = "nmap 127.0.0.1"
        data = {"cmd": cmd}
        response = requests.post(self.url_input,
                                 data=json.dumps(data),
                                 headers=self.headers)
        json_response = response.json()

        self.assertEquals(response.status_code, 200, "Status Code should be 200: OK, but received: %d" % response.status_code)
        self.assertIn("cmd", json_response.keys(), "Json response should have a cmd key")
        self.assertIn("custom_output_file", json_response.keys(), "Json response should have a custom_output_file key")
        self.assertIsNotNone(json_response.get("cmd"), "cmd shouldn't be None")
        self.assertIsNotNone(json_response.get("custom_output_file"), "custom_output_file shouldn't be None")

    def test_cmd_input_get_instead_post(self):
        cmd = "ls"
        data = {"cmd": cmd}
        response = requests.get(self.url_input,
                                data=json.dumps(data),
                                headers=self.headers)

        self.assertEquals(response.status_code, 405, "Status code should be 405, but received: %d" % response.status_code)

    def test_cmd_output_nmap(self):
        # send input to register the active plugin
        cmd = "nmap 127.0.0.1"
        data = {"cmd": cmd}
        response = requests.post(self.url_input,
                                 data=json.dumps(data),
                                 headers=self.headers)

        #send output, using a fake nmap xml ouput
        output_file = open(os.path.join(os.getcwd(), 'test_cases/data/nmap_plugin_with_api.xml'))
        output = output_file.read()
        data = {"cmd": cmd, "output": output}
        response = requests.post(self.url_output,
                                 data=json.dumps(data),
                                 headers=self.headers)
        self.model_controller.processAllPendingActions()

        self.assertEquals(response.status_code, 200, "Status Code should be 200: OK, but received: %d" % response.status_code)
        self.assertEquals(len(self.model_controller.getAllHosts()), 1, "Controller should have 1 host")

    def test_cmd_output_plugin_not_active(self):
        #send output, using a fake nmap xml ouput
        cmd = "nmap 127.0.0.1"
        output_file = open(os.path.join(os.getcwd(), 'test_cases/data/nmap_plugin_with_api.xml'))
        output = output_file.read()
        data = {"cmd": cmd, "output": output}
        response = requests.post(self.url_output,
                                 data=json.dumps(data),
                                 headers=self.headers)

        self.assertEquals(response.status_code, 400, "Status Code should be 400: Bad Request, but received: %d" % response.status_code)

if __name__ == '__main__':
    unittest.main()
