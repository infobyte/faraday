#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''


import os
import re
import time
import logging
import traceback
import deprecation
from threading import Thread

import faraday.server.config
import faraday.client.model.api
import faraday.client.model.common
from faraday import __license_version__ as license_version
from faraday.client.model.common import factory
from faraday.client.persistence.server.models import get_host , update_host
from faraday.client.persistence.server.models import (
    Host,
    Service,
    Vuln,
    VulnWeb,
    Credential,
    Note
)
from faraday.client.model import Modelactions
#from plugins.modelactions import modelactions

from faraday.config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()
VERSION = license_version.split('-')[0].split('rc')[0]
logger = logging.getLogger(__name__)


class PluginBase(object):
    # TODO: Add class generic identifier
    class_signature = "PluginBase"

    def __init__(self):

        self.data_path = CONF.getDataPath()
        self.persistence_path = CONF.getPersistencePath()
        self.workspace = CONF.getLastWorkspace()
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
        self._settings = {}
        self.command_id = None

    def has_custom_output(self):
        return bool(self._output_file_path)

    def get_custom_file_path(self):
        return self._output_file_path

    def set_actions_queue(self, _pending_actions):
        """
            We use plugin controller queue to add actions created by plugins.
            Plugin controller will consume this actions.

        :param controller: plugin controller
        :return: None
        """
        self._pending_actions = _pending_actions

    def setCommandID(self, command_id):
        self.command_id = command_id

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
            if name in self._settings:
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
            self._parse_filename(self.get_custom_file_path())
        else:
            self.parseOutputString(output)

    def _parse_filename(self, filename):
        with open(filename, 'rb') as output:
            self.parseOutputString(output.read())

    def processReport(self, filepath):
        if os.path.isfile(filepath):
            self._parse_filename(filepath)

    def parseOutputString(self, output):
        """
        This method must be implemented.
        This method will be called when the command finished executing and
        the complete output will be received to work with it
        Using the output the plugin can create and add hosts, interfaces,
        services, etc.
        """
        raise NotImplementedError('This method must be implemented.')

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

        if self.command_id:
            args = args + (self.command_id, )
        else:
            logger.warn('Warning command id not set for action {0}'.format(args))
        logger.debug('AddPendingAction %s', args)
        self._pending_actions.put(args)

    def createAndAddHost(self, name, os="unknown", hostnames=None, mac=None):

        host_obj = factory.createModelObject(
            Host.class_signature,
            name,
            os=os,
            parent_id=None,
            workspace_name=self.workspace,
            hostnames=hostnames,
            mac=mac)

        host_obj._metadata.creatoserverr = self.id
        self.__addPendingAction(Modelactions.ADDHOST, host_obj)
        return host_obj.getID()

    @deprecation.deprecated(deprecated_in="3.0", removed_in="3.5",
                            current_version=VERSION,
                            details="Interface object removed. Use host or service instead")
    def createAndAddInterface(
        self, host_id, name="", mac="00:00:00:00:00:00",
        ipv4_address="0.0.0.0", ipv4_mask="0.0.0.0", ipv4_gateway="0.0.0.0",
        ipv4_dns=[], ipv6_address="0000:0000:0000:0000:0000:0000:0000:0000",
        ipv6_prefix="00",
        ipv6_gateway="0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns=[],
        network_segment="", hostname_resolution=[]):

        # We don't use interface anymore, so return a host id to maintain
        # backwards compatibility
        # Little hack because we dont want change all the plugins for add hostnames in Host object.
        # SHRUG
        try:
            host = get_host(self.workspace, host_id=host_id)
            host.hostnames += hostname_resolution
            host.mac = mac
            update_host(self.workspace, host, command_id=self.command_id)
        except:
            logger.info("Error updating Host with right hostname resolution...")
        return host_id

    @deprecation.deprecated(deprecated_in="3.0", removed_in="3.5",
                            current_version=VERSION,
                            details="Interface object removed. Use host or service instead. Service will be attached to Host!")
    def createAndAddServiceToInterface(self, host_id, interface_id, name,
                                       protocol="tcp?", ports=[],
                                       status="open", version="unknown",
                                       description=""):
        if status not in ("open", "closed", "filtered"):
            self.log(
                'Unknown service status %s. Using "open" instead' % status,
                'WARNING'
            )
            status = 'open'

        serv_obj = faraday.client.model.common.factory.createModelObject(
            Service.class_signature,
            name, protocol=protocol, ports=ports, status=status,
            version=version, description=description,
            parent_type='Host', parent_id=host_id,
            workspace_name=self.workspace)

        serv_obj._metadata.creator = self.id
        self.__addPendingAction(Modelactions.ADDSERVICEHOST, serv_obj)
        return serv_obj.getID()

    def createAndAddServiceToHost(self, host_id, name,
                                       protocol="tcp?", ports=[],
                                       status="open", version="unknown",
                                       description=""):
        if status not in ("open", "closed", "filtered"):
            self.log(
                'Unknown service status %s. Using "open" instead' % status,
                'WARNING'
            )
            status = 'open'

        serv_obj = faraday.client.model.common.factory.createModelObject(
            Service.class_signature,
            name, protocol=protocol, ports=ports, status=status,
            version=version, description=description,
            parent_type='Host', parent_id=host_id,
            workspace_name=self.workspace)

        serv_obj._metadata.creator = self.id
        self.__addPendingAction(Modelactions.ADDSERVICEHOST, serv_obj)
        return serv_obj.getID()

    def createAndAddVulnToHost(self, host_id, name, desc="", ref=[],
                               severity="", resolution="", data=""):

        vuln_obj = faraday.client.model.common.factory.createModelObject(
            Vuln.class_signature,
            name, data=data, desc=desc, refs=ref, severity=severity,
            resolution=resolution, confirmed=False,
            parent_id=host_id, parent_type='Host',
            workspace_name=self.workspace)

        vuln_obj._metadata.creator = self.id
        self.__addPendingAction(Modelactions.ADDVULNHOST, vuln_obj)
        return vuln_obj.getID()

    @deprecation.deprecated(deprecated_in="3.0", removed_in="3.5",
                            current_version=VERSION,
                            details="Interface object removed. Use host or service instead. Vuln will be added to Host")
    def createAndAddVulnToInterface(self, host_id, interface_id, name,
                                    desc="", ref=[], severity="",
                                    resolution="", data=""):

        vuln_obj = faraday.client.model.common.factory.createModelObject(
            Vuln.class_signature,
            name, data=data, desc=desc, refs=ref, severity=severity,
            resolution=resolution, confirmed=False,
            parent_type='Host', parent_id=host_id,
            workspace_name=self.workspace)

        vuln_obj._metadata.creator = self.id
        self.__addPendingAction(Modelactions.ADDVULNHOST, vuln_obj)
        return vuln_obj.getID()

    def createAndAddVulnToService(self, host_id, service_id, name, desc="",
                                  ref=[], severity="", resolution="", data=""):

        vuln_obj = faraday.client.model.common.factory.createModelObject(
            Vuln.class_signature,
            name, data=data, desc=desc, refs=ref, severity=severity,
            resolution=resolution, confirmed=False,
            parent_type='Service', parent_id=service_id,
            workspace_name=self.workspace)

        vuln_obj._metadata.creator = self.id
        self.__addPendingAction(Modelactions.ADDVULNSRV, vuln_obj)
        return vuln_obj.getID()

    def createAndAddVulnWebToService(self, host_id, service_id, name, desc="",
                                     ref=[], severity="", resolution="",
                                     website="", path="", request="",
                                     response="", method="", pname="",
                                     params="", query="", category="", data=""):
        vulnweb_obj = faraday.client.model.common.factory.createModelObject(
            VulnWeb.class_signature,
            name, data=data, desc=desc, refs=ref, severity=severity,
            resolution=resolution, website=website, path=path,
            request=request, response=response, method=method,
            pname=pname, params=params, query=query,
            category=category, confirmed=False, parent_id=service_id,
            parent_type='Service',
            workspace_name=self.workspace)

        vulnweb_obj._metadata.creator = self.id
        self.__addPendingAction(Modelactions.ADDVULNWEBSRV, vulnweb_obj)
        return vulnweb_obj.getID()

    def createAndAddNoteToHost(self, host_id, name, text):
        return None

    def createAndAddNoteToInterface(self, host_id, interface_id, name, text):
        return None

    def createAndAddNoteToService(self, host_id, service_id, name, text):
        return None

    def createAndAddNoteToNote(self, host_id, service_id, note_id, name, text):
        return None

    def createAndAddCredToService(self, host_id, service_id, username,
                                  password):

        cred_obj = faraday.client.model.common.factory.createModelObject(
            Credential.class_signature,
            username, password=password, parent_id=service_id, parent_type='Service',
            workspace_name=self.workspace)

        cred_obj._metadata.creator = self.id
        self.__addPendingAction(Modelactions.ADDCREDSRV, cred_obj)
        return cred_obj.getID()

    def log(self, msg, level='INFO'):
        self.__addPendingAction(Modelactions.LOG, msg, level)

    def devlog(self, msg):
        self.__addPendingAction(Modelactions.DEVLOG, msg)


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


class PluginProcess(Thread):
    def __init__(self, plugin_instance, output_queue, isReport=False):
        """
            Executes one plugin.

        :param plugin_instance: current plugin in execution.
        :param output_queue: queue with raw ouput of that the plugin needs.
        :param isReport: output data was read from file.
        """
        super(PluginProcess, self).__init__()
        self.output_queue = output_queue
        self.plugin = plugin_instance
        self.isReport = isReport
        self.setDaemon(True)
        self.stop = False

    def run(self):
        proc_name = self.name
        faraday.client.model.api.devlog("-" * 40)
        faraday.client.model.api.devlog("proc_name = %s" % proc_name)
        faraday.client.model.api.devlog("Starting run method on PluginProcess")
        faraday.client.model.api.devlog('parent process: %s' % os.getppid())
        faraday.client.model.api.devlog('process id: %s' % os.getpid())
        faraday.client.model.api.devlog("-" * 40)
        done = False
        while not done and not self.stop:
            output, command_id = self.output_queue.get()
            self.plugin.setCommandID(command_id)
            if output is not None:
                faraday.client.model.api.devlog('%s: %s' % (proc_name, "New Output"))
                try:
                    self.plugin.processOutput(output)
                except Exception as ex:
                    faraday.client.model.api.devlog("Plugin raised an exception:")
                    faraday.client.model.api.devlog(traceback.format_exc())
            else:
                done = True
                faraday.client.model.api.devlog('%s: Exiting' % proc_name)

            self.output_queue.task_done()
            time.sleep(0.1)

        return

    def stop(self):
        self.stop = True