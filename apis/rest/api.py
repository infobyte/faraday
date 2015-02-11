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
from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


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
        _http_server.stop()


def startAPIs(plugin_manager, model_controller, mapper_manager, hostname=None, port=None):
    global _rest_controllers
    global _http_server
    _rest_controllers = [PluginControllerAPI(plugin_manager, mapper_manager), ModelControllerAPI(model_controller)]

    #TODO: some way to get defaults.. from config?
    if str(hostname) == "None":
        hostname = "localhost"
    if str(port) == "None":
        port = 9977

    if CONF.getApiRestfulConInfo() is None:
        CONF.setApiRestfulConInfo(hostname, port)

    app = Flask('APISController')

    _http_server = HTTPServer(WSGIContainer(app))
    _http_server.listen(port,address=hostname) 

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

        routes.append(Route(path='/model/host',
                            view_func=self.createHost,
                            methods=['PUT']))

        routes.append(Route(path='/model/webvulns',
                            view_func=self.listWebVulns,
                            methods=['GET']))

        routes.append(Route(path='/model/interface',
                            view_func=self.createInterface,
                            methods=['PUT']))

        routes.append(Route(path='/model/service',
                            view_func=self.createService,
                            methods=['PUT']))

        routes.append(Route(path='/model/vuln',
                            view_func=self.createVuln,
                            methods=['PUT']))

        routes.append(Route(path='/model/vulnweb',
                            view_func=self.createVulnWeb,
                            methods=['PUT']))

        routes.append(Route(path='/model/note',
                            view_func=self.createNote,
                            methods=['PUT']))

        routes.append(Route(path='/model/cred',
                            view_func=self.createCred,
                            methods=['PUT']))

        return routes

    def listWebVulns(self):
        vulns = self.controller.getWebVulns()
        j = [{'request': v.request, 'website': v.website, 'path': v.path, 'name': v.name,
            'desc': v.desc, 'severity': v.severity, 'resolution': v.resolution} for v in vulns]
        return self.ok(j)

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
        resolution = json_data.get('resolution', None)
        refs = json_data.get('refs', None)

        # forward to controller 
        for vuln in visitor.vulns: 
            self.controller.editVulnSYNC(vuln, name, desc, severity, resolution, refs) 

        return self.ok("output successfully sent to plugin")

    def _create(self, creation_callback, params):
        data = request.get_json()
        if not 'name' in data:
            return self.badRequest("name is mandatory")

        kwargs = {}
        for param in params:
            kwargs[param] = data.get(param, None)
        obj = creation_callback(**kwargs)

        if obj:
            return jsonify(code=200,
                           id=obj.getID())
        return self.badRequest("Object cannot be created")

    def createHost(self):
        return self._create(
            self.controller.newHost,
            ['name', 'os'])

    def createInterface(self):
        return self._create(
            self.controller.newInterface,
            ['name', 'mac', 'ipv6_address', 'ipv4_mask', 'ipv4_gateway',
             'ipv4_dns', 'ipv6_address', 'ipv6_prefix', 'ipv6_gateway',
             'ipv6_dns', 'network_segment', 'hostname_resolution',
             'parent_id'])

    def createService(self):
        return self._create(
            self.controller.newService,
            ['name', 'protocol', 'ports', 'status',
             'version', 'description', 'parent_id'])

    def createVuln(self):
        return self._create(
            self.controller.newVuln,
            ['name', 'desc', 'ref', 'severity', 'resolution', 'parent_id'])

    def createVulnWeb(self):
        return self._create(
            self.controller.newVulnWeb,
            ['name', 'desc', 'ref', 'severity', 'resolution', 'website',
             'path', 'request', 'response', 'method', 'pname',
             'params', 'query', 'category', 'parent_id'])

    def createNote(self):
        return self._create(
            self.controller.newNote,
            ['name', 'text', 'parent_id'])

    def createCred(self):
        return self._create(
            self.controller.newCred,
            ['username', 'password', 'parent_id'])


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
