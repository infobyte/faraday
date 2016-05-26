#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import multiprocessing
import os
import re
import Queue
import traceback

import model.api
import model.common
from model.common import (
    factory,
    ModelObjectVuln,
    ModelObjectVulnWeb,
    ModelObjectNote,
    ModelObjectCred
)
from model.hosts import Host, Interface, Service
from plugins.modelactions import modelactions

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class PluginBase(object):
    # TODO: Add class generic identifier
    class_signature = "PluginBase"

    def __init__(self):

        self.data_path = CONF.getDataPath()
        self.persistence_path = CONF.getPersistencePath()
        # Must be unique. Check that there is not
        # an existant plugin with the same id.
        # TODO: Make script that list current ids.
        self.id = None
        self._rid = id(self)
        self.version = None
        self.name = None
        self.description = ""
        self._command_regex = None
        self._output_file_path = None
        self.framework_version = None
        self._completition = {}
        self._new_elems = []
        self._pending_actions = Queue.Queue()
        self._settings = {}

    def has_custom_output(self):
        return bool(self._output_file_path)

    def get_custom_file_path(self):
        return self._output_file_path

    def getSettings(self):
        for param, (param_type, value) in self._settings.iteritems():
            yield param, value

    def get_ws(self):
        return CONF.getLastWorkspace()

    def getSetting(self, name):
        setting_type, value = self._settings[name]
        return value

    def addSetting(self, param, param_type, value):
        self._settings[param] = param_type, value

    def updateSettings(self, new_settings):
        for name, value in new_settings.iteritems():
            setting_type, curr_value = self._settings[name]
            self._settings[name] = setting_type, setting_type(value)

    def canParseCommandString(self, current_input):
        """
        This method can be overriden in the plugin implementation
        if a different kind of check is needed
        """
        return (self._command_regex is not None and
                self._command_regex.match(current_input.strip()) is not None)

    def getCompletitionSuggestionsList(self, current_input):
        """
        This method can be overriden in the plugin implementation
        if a different kind of check is needed
        """
        words = current_input.split(" ")
        cword = words[len(words) - 1]

        options = {}
        for k, v in self._completition.iteritems():
            if re.search(str("^" + cword), k, flags=re.IGNORECASE):
                options[k] = v

        return options

    def processOutput(self, term_output):
        output = term_output
        if self.has_custom_output() and os.path.isfile(self.get_custom_file_path()):
            output = open(self.get_custom_file_path(), 'r').read()
        self.parseOutputString(output)

    def processReport(self, filepath):
        if os.path.isfile(filepath):
            output = open(filepath, 'r').read()
            self.parseOutputString(output)

    def parseOutputString(self, output):
        """
        This method must be implemented.
        This method will be called when the command finished executing and
        the complete output will be received to work with it
        Using the output the plugin can create and add hosts, interfaces,
        services, etc.
        """
        pass

    def processCommandString(self, username, current_path, command_string):
        """
        With this method a plugin can add aditional arguments to the
        command that it's going to be executed.
        """
        return None

    def __addPendingAction(self, *args):
        """
        Adds a new pending action to the queue
        Action is build with generic args tuple.
        The caller of this function has to build the action in the right
        way since no checks are preformed over args
        """
        self._pending_actions.put(args)

    def createAndAddHost(self, name, os="unknown", category=None,
                         update=False, old_hostname=None):
        self.__addPendingAction(modelactions.CADDHOST, name, os, category,
                                update, old_hostname)
        return factory.generateID(Host.class_signature, name=name, os=os)

    def createAndAddInterface(
        self, host_id, name="", mac="00:00:00:00:00:00",
        ipv4_address="0.0.0.0", ipv4_mask="0.0.0.0", ipv4_gateway="0.0.0.0",
        ipv4_dns=[], ipv6_address="0000:0000:0000:0000:0000:0000:0000:0000",
        ipv6_prefix="00",
        ipv6_gateway="0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns=[],
        network_segment="", hostname_resolution=[]
    ):
        self.__addPendingAction(modelactions.CADDINTERFACE, host_id, name,
                                mac, ipv4_address, ipv4_mask, ipv4_gateway,
                                ipv4_dns, ipv6_address, ipv6_prefix,
                                ipv6_gateway, ipv6_dns,
                                network_segment, hostname_resolution)
        return factory.generateID(
            Interface.class_signature, parent_id=host_id, name=name, mac=mac,
            ipv4_address=ipv4_address, ipv4_mask=ipv4_mask,
            ipv4_gateway=ipv4_gateway, ipv4_dns=ipv4_dns,
            ipv6_address=ipv6_address, ipv6_prefix=ipv6_prefix,
            ipv6_gateway=ipv6_gateway, ipv6_dns=ipv6_dns,
            network_segment=network_segment,
            hostname_resolution=hostname_resolution)

    def createAndAddServiceToInterface(self, host_id, interface_id, name,
                                       protocol="tcp?", ports=[],
                                       status="running", version="unknown",
                                       description=""):
        self.__addPendingAction(modelactions.CADDSERVICEINT, host_id,
                                interface_id, name, protocol, ports, status,
                                version, description)
        return factory.generateID(
            Service.class_signature,
            name=name, protocol=protocol, ports=ports,
            status=status, version=version, description=description,
            parent_id=interface_id)

    def createAndAddVulnToHost(self, host_id, name, desc="", ref=[],
                               severity="", resolution=""):
        self.__addPendingAction(modelactions.CADDVULNHOST, host_id, name,
                                desc, ref, severity, resolution)
        return factory.generateID(
            ModelObjectVuln.class_signature,
            name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, parent_id=host_id)

    def createAndAddVulnToInterface(self, host_id, interface_id, name,
                                    desc="", ref=[], severity="",
                                    resolution=""):
        self.__addPendingAction(modelactions.CADDVULNINT, host_id,
                                interface_id, name, desc, ref, severity,
                                resolution)
        return factory.generateID(
            ModelObjectVuln.class_signature,
            name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, parent_id=interface_id)

    def createAndAddVulnToService(self, host_id, service_id, name, desc="",
                                  ref=[], severity="", resolution=""):
        self.__addPendingAction(modelactions.CADDVULNSRV, host_id,
                                service_id, name, desc, ref, severity,
                                resolution)
        return factory.generateID(
            ModelObjectVuln.class_signature,
            name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, parent_id=service_id)

    def createAndAddVulnWebToService(self, host_id, service_id, name, desc="",
                                     ref=[], severity="", resolution="",
                                     website="", path="", request="",
                                     response="", method="", pname="",
                                     params="", query="", category=""):
        self.__addPendingAction(modelactions.CADDVULNWEBSRV, host_id,
                                service_id, name, desc, ref, severity,
                                resolution, website, path, request, response,
                                method, pname, params, query, category)
        return factory.generateID(
            ModelObjectVulnWeb.class_signature,
            name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, website=website, path=path, request=request,
            response=response, method=method, pname=pname, params=params,
            query=query, category=category, parent_id=service_id)

    def createAndAddNoteToHost(self, host_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTEHOST, host_id, name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=host_id)

    def createAndAddNoteToInterface(self, host_id, interface_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTEINT, host_id, interface_id,
                                name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=interface_id)

    def createAndAddNoteToService(self, host_id, service_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTESRV, host_id, service_id,
                                name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=service_id)

    def createAndAddNoteToNote(self, host_id, service_id, note_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTENOTE, host_id, service_id,
                                note_id, name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=note_id)

    def createAndAddCredToService(self, host_id, service_id, username,
                                  password):
        self.__addPendingAction(modelactions.CADDCREDSRV, host_id, service_id,
                                username, password)
        return factory.generateID(
            ModelObjectCred.class_signature,
            username=username, password=password, parent_id=service_id)

    def addHost(self, host, category=None, update=False, old_hostname=None):
        self.__addPendingAction(modelactions.ADDHOST, host, category, update,
                                old_hostname)

    def addInterface(self, host_id, interface):
        self.__addPendingAction(modelactions.ADDINTERFACE, host_id, interface)

    def addApplication(self, host_id, application):
        self.__addPendingAction(modelactions.ADDAPPLICATION, host_id,
                                application)

    def addServiceToApplication(self, host_id, application_id, service):
        self.__addPendingAction(modelactions.ADDSERVICEAPP, host_id,
                                application_id, service)

    def addServiceToInterface(self, host_id, interface_id, service):
        self.__addPendingAction(modelactions.ADDSERVICEINT, host_id,
                                interface_id, service)

    def addVulnToHost(self, host_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNHOST, host_id, vuln)

    def addVulnToInterface(self, host_id, interface_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNINT, host_id, interface_id,
                                vuln)

    def addVulnToApplication(self, host_id, application_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNAPP, host_id,
                                application_id, vuln)

    def addVulnToService(self, host_id, service_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNSRV, host_id, service_id,
                                vuln)

    def addVulnWebToService(self, host_id, service_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNWEBSRV, host_id, service_id,
                                vuln)

    def addNoteToHost(self, host_id, note):
        self.__addPendingAction(modelactions.ADDNOTEHOST, host_id, note)

    def addNoteToInterface(self, host_id, interface_id, note):
        self.__addPendingAction(modelactions.ADDNOTEINT, host_id, interface_id,
                                note)

    def addNoteToApplication(self, host_id, application_id, note):
        self.__addPendingAction(modelactions.ADDNOTEAPP, host_id,
                                application_id, note)

    def addNoteToService(self, host_id, service_id, note):
        self.__addPendingAction(modelactions.ADDNOTESRV, host_id, service_id,
                                note)

    def addNoteToNote(self, host_id, service_id, note_id, note):
        self.__addPendingAction(modelactions.ADDNOTENOTE, host_id, service_id,
                                note_id, note)

    def addCredToService(self, host_id, service_id, cred):
        self.__addPendingAction(modelactions.ADDCREDSRV, host_id, service_id,
                                cred)

    def delServiceFromInterface(self, service, hostname,
                                intname, remote=True):
        self.__addPendingAction(modelactions.DELSERVICEINT, hostname, intname,
                                service, remote)

    def log(self, msg, level='INFO'):
        self.__addPendingAction(modelactions.LOG, msg, level)

    def devlog(self, msg):
        self.__addPendingAction(modelactions.DEVLOG, msg)


class PluginTerminalOutput(PluginBase):
    def __init__(self):
        super(PluginTerminalOutput, self).__init__()

    def processOutput(self, term_output):
        self.parseOutputString(term_output)


class PluginCustomOutput(PluginBase):
    def __init__(self):
        super(PluginCustomOutput, self).__init__()

    def processOutput(self, term_output):
        # we discard the term_output since it's not necessary
        # for this type of plugins
        self.processReport(self._output_file_path)


class PluginProcess(multiprocessing.Process):
    def __init__(self, plugin_instance, output_queue, new_elem_queue, isReport=False):
        multiprocessing.Process.__init__(self)
        self.output_queue = output_queue
        self.new_elem_queue = new_elem_queue
        self.plugin = plugin_instance
        self.isReport = isReport

    def run(self):
        proc_name = self.name
        model.api.devlog("-" * 40)
        model.api.devlog("proc_name = %s" % proc_name)
        model.api.devlog("Starting run method on PluginProcess")
        model.api.devlog('parent process: %s' % os.getppid())
        model.api.devlog('process id: %s' % os.getpid())
        model.api.devlog("-" * 40)
        done = False
        while not done:
            output = self.output_queue.get()
            if output is not None:
                model.api.devlog('%s: %s' % (proc_name, "New Output"))
                try:
                    if self.isReport:
                        self.plugin.processReport(output)
                    else:
                        self.plugin.processOutput(output)
                except Exception:
                    model.api.devlog("Plugin raised an exception:")
                    model.api.devlog(traceback.format_exc())
                else:
                    while True:
                        try:
                            self.new_elem_queue.put(
                                self.plugin._pending_actions.get(block=False))
                        except Queue.Empty:
                            model.api.devlog(
                                ("PluginProcess run _pending_actions"
                                 " queue Empty. Breaking loop"))
                            break
                        except Exception:
                            model.api.devlog(
                                ("PluginProcess run getting from "
                                 "_pending_action queue - something strange "
                                 "happened... unhandled exception?"))
                            model.api.devlog(traceback.format_exc())
                            break

            else:

                done = True
                model.api.devlog('%s: Exiting' % proc_name)

            self.output_queue.task_done()
        self.new_elem_queue.put(None)
        return
