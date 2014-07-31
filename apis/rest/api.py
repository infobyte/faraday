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
from model.visitor import VulnsLookupVisitor

import utils.logs as logger


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


def startAPIs(plugin_manager, model_controller, mapper_manager):
    global _rest_controllers
    global _http_server
    _rest_controllers = [PluginControllerAPI(plugin_manager, mapper_manager), ModelControllerAPI(model_controller)]
    #TODO: load API configuration from config file
    hostname = "localhost"
    port = 9977
    app = Flask('APISController')

    _http_server = HTTPServer(WSGIContainer(app))
    _http_server.listen(port) 

    routes = [r for c in _rest_controllers for r in c.getRoutes()]

    for route in routes: 
        app.add_url_rule(route.path, view_func=route.view_func, methods=route.methods) 

    logging.getLogger("tornado.access").addHandler(logger.getLogger(app))
    logging.getLogger("tornado.access").propagate = False
    threading.Thread(target=startServer).start()

def stopAPIs():
    stopServer()


class RESTApi(object):
    """ Abstract class for REST Controllers
    All REST Controllers should extend this class
    in order to get published"""

    def getRoutes(self):
        raise NotImplementedError('Abstract Class')

    def badRequest(self, message):
        error = 400
        return jsonify(error=error,
                       message=message), error

    def noContent(self, message):
        code = 204
        return jsonify(code=code,
                       message=message), code

    def ok(self, message):
        code = 200
        return jsonify(code=code,
                       message=message)

class ModelControllerAPI(RESTApi):
    def __init__(self, model_controller):
        self.controller = model_controller

    def getRoutes(self):
        routes = []
        routes.append(Route(path='/model/edit/vulns',
                              view_func=self.postEditVulns,
                              methods=['POST']))

        routes.append(Route(path='/model/del/vulns',
                              view_func=self.deleteVuln,
                              methods=['DELETE']))
        return routes


        return host

    def deleteVuln(self):
        json_data = request.get_json()
        # validate mandatory:
        if not 'vulnid' in json_data:
            return self.badRequest("vulid is mandatory")
        if not 'hostid' in json_data:
            return self.badRequest("hostid is mandatory")

        vulnid = json_data['vulnid']
        hostid = json_data['hostid']

        host = self.controller.getHost(hostid)
        if not host: 
            return self.badRequest("no plugin available for cmd") 

        visitor = VulnsLookupVisitor(vulnid)
        host.accept(visitor)

        if not visitor.vulns:
            return self.noContent('No vuls matched criteria')

        # forward to controller 
        for vuln, parents in zip(visitor.vulns, visitor.parents):
            last_parent = parents[0]
            self.controller.delVulnSYNC(last_parent, vuln.getID())

        return self.ok("output successfully sent to plugin")


    def postEditVulns(self):
        json_data = request.get_json()
        # validate mandatory:
        if not 'vulnid' in json_data:
            return self.badRequest("vulid is mandatory")
        if not 'hostid' in json_data:
            return self.badRequest("hostid is mandatory")

        vulnid = json_data['vulnid']
        hostid = json_data['hostid']

        host = self.controller.getHost(hostid)
        if not host: 
            return self.badRequest("no plugin available for cmd") 

        visitor = VulnsLookupVisitor(vulnid)
        host.accept(visitor)

        if not visitor.vulns:
            return self.noContent('No vuls matched criteria')

        name = json_data.get('name', None)
        desc = json_data.get('desc', None)
        severity = json_data.get('severity', None)
        refs = json_data.get('refs', None)

        # forward to controller 
        for vuln in visitor.vulns: 
            self.controller.editVulnSYNC(vuln, name, desc, severity, refs) 

        return self.ok("output successfully sent to plugin")

class PluginControllerAPI(RESTApi):
    def __init__(self, plugin_manager, mapper_manager):
        self.plugin_controller = PluginControllerForApi(
            "PluginController",
            plugin_manager.getPlugins(),
            mapper_manager)

    def getRoutes(self):
        routes = []
        routes.append(Route(path='/cmd/input',
                              view_func=self.postCmdInput,
                              methods=['POST']))
        routes.append(Route(path='/cmd/output',
                              view_func=self.postCmdOutput,
                              methods=['POST']))
        routes.append(Route(path='/cmd/active-plugins',
                              view_func=self.clearActivePlugins,
                              methods=['DELETE']))
        return routes

    def pluginAvailable(self, new_cmd, output_file):
        code = 200
        return jsonify(code=code,
                       cmd=new_cmd,
                       custom_output_file=output_file)

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


class Route(object):
    """ Route class, abstracts information about:
    path, handler and methods """
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
