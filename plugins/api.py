#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import threading
import logging
import requests
import json
import base64

from flask import Flask, request, jsonify
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

from plugins.core import PluginControllerForApi
from managers.all import CommandManager


_plugin_controller_api = None
_http_server = None


def startServer():
    global _http_server
    if _http_server is not None:
        IOLoop.instance().start()


def stopServer():
    global _http_server
    if _http_server is not None:
        IOLoop.instance().stop()


def startPluginControllerAPI(plugin_manager):
    global _plugin_controller_api
    global _http_server
    if _plugin_controller_api is None:
        #TODO: load API configuration from config file
        hostname = "localhost"
        port = 9977
        _plugin_controller_api = PluginControllerAPI(plugin_manager,
                                                     hostname,
                                                     port)
        if _http_server is None:
            _http_server = HTTPServer(WSGIContainer(_plugin_controller_api.getApp()))
            _http_server.listen(port)
            logging.getLogger("tornado.access").addHandler(logging.NullHandler())
            logging.getLogger("tornado.access").propagate = False
            threading.Thread(target=startServer).start()


def stopPluginControllerAPI():
    stopServer()


class PluginControllerAPI(object):
    def __init__(self, plugin_manager, hostname, port):
        self.plugin_controller = PluginControllerForApi("PluginController", plugin_manager.getPlugins(), CommandManager())
        self.app = Flask(__name__.split('.')[0])
        self.addRoutes()
        self.hostname = hostname
        self.port = port
        #self.api = Api(self.app)

    def getApp(self):
        return self.app

    #def run(self):
    #    self.app.run(host=self.hostname, port=self.port)

    def addRoutes(self):
        self.app.add_url_rule('/cmd/input',
                              view_func=self.postCmdInput,
                              methods=['POST'])
        self.app.add_url_rule('/cmd/output',
                              view_func=self.postCmdOutput,
                              methods=['POST'])
        self.app.add_url_rule('/cmd/active-plugins',
                              view_func=self.clearActivePlugins,
                              methods=['DELETE'])

    def startAPI(self):
        pass

    def stopAPI(self):
        pass

    def badRequest(self, message):
        error = 400
        return jsonify(error=error,
                       message=message), error

    def noContent(self, message):
        code = 204
        return jsonify(code=code,
                       message=message), code

    def pluginAvailable(self, new_cmd, output_file):
        code = 200
        return jsonify(code=code,
                       cmd=new_cmd,
                       custom_output_file=output_file)

    def ok(self, message):
        code = 200
        return jsonify(code=code,
                       message=message)

    def postCmdInput(self):
        json_data = request.get_json()
        if 'cmd' in json_data.keys():
            cmd = json_data.get('cmd')
            has_plugin, new_cmd, output_file = self.plugin_controller.\
                processCommandInput(cmd)
            if has_plugin:
                return self.pluginAvailable(new_cmd, output_file)
            return self.noContent("no plugin available for cmd")
        #cmd not sent, bad request
        return self.badRequest("cmd parameter not sent")

    def postCmdOutput(self):
        json_data = request.get_json()
        if 'cmd' in json_data.keys():
            if 'output' in json_data.keys():
                cmd = json_data.get('cmd')
                output = base64.b64decode(json_data.get('output'))
                if self.plugin_controller.onCommandFinished(cmd, output):
                    return self.ok("output successfully sent to plugin")
                return self.badRequest("output received but no active plugin")
            return self.badRequest("output parameter not sent")
        return self.badRequest("cmd parameter not sent")

    def clearActivePlugins(self):
        self.plugin_controller.clearActivePlugins()
        return self.ok("active plugins cleared")


class PluginControllerAPIClient(object):
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.url_input = "http://%s:%d/cmd/input" % (self.hostname, self.port)
        self.url_output = "http://%s:%d/cmd/output" % (self.hostname, self.port)
        self.url_active_plugins = "http://%s:%d/cmd/active-plugins" % (self.hostname, self.port)
        self.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

    def send_cmd(self, cmd):
        data = {"cmd": cmd}
        new_cmd = cmd
        try:
            response = requests.post(self.url_input,
                                     data=json.dumps(data),
                                     headers=self.headers)

            if response.status_code == 200:
                json_response = response.json()
                if "cmd" in json_response.keys():
                    if json_response.get("cmd") is not None:
                        new_cmd = json_response.get("cmd")
                if "custom_output_file" in json_response.keys():
                    output_file = json_response.get("custom_output_file")
        except:
            new_cmd = cmd
        finally:
            return new_cmd, output_file

    def send_output(self, cmd, output_file):
        output_file = open(output_file)
        output = base64.b64encode(output_file.read())
        data = {"cmd": cmd, "output": output}
        response = requests.post(self.url_output,
                                 data=json.dumps(data),
                                 headers=self.headers)
        if response.status_code != 200:
            return False
        return True