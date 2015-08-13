#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import multiprocessing
import shlex
import copy_reg
import types
import model.api
from cStringIO import StringIO
import os
import re
import Queue
import traceback
import model.common
import errno
from model.common import factory, ModelObjectVuln, ModelObjectVulnWeb, ModelObjectNote, ModelObjectCred
from model.hosts import Host, Interface, Service

from model.commands_history import CommandRunInformation
from utils.common import sha1OfStr

from time import time

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


def _pickle_method(method):
    func_name = method.im_func.__name__
    obj = method.im_self
    cls = method.im_class
    return _unpickle_method, (func_name, obj, cls)


def _unpickle_method(func_name, obj, cls):
    for cls in cls.mro():
        try:
            func = cls.__dict__[func_name]
        except KeyError:
            pass
        else:
            break
        return func.__get__(obj, cls)

copy_reg.pickle(types.MethodType, _pickle_method, _unpickle_method)


class modelactions:
    ADDHOST             = 2000
    CADDHOST            = 2001
    ADDINTERFACE        = 2002
    CADDINTERFACE       = 2003
    ADDSERVICEINT       = 2004
    ADDSERVICEAPP       = 2005
    CADDSERVICEINT      = 2006
    CADDSERVICEAPP      = 2007
    CADDSERVICEHOST     = 2008
    ADDAPPLICATION      = 2009
    CADDAPPLICATION     = 2010
    ADDVULNINT          = 2013
    CADDVULNINT         = 2014
    ADDVULNAPP          = 2015
    CADDVULNAPP         = 2016
    ADDVULNHOST         = 2017
    CADDVULNHOST        = 2018
    ADDVULNSRV          = 2019
    CADDVULNSRV         = 2020
    ADDNOTEINT          = 2021
    CADDNOTEINT         = 2022
    ADDNOTEAPP          = 2023
    CADDNOTEAPP         = 2024
    ADDNOTEHOST         = 2025
    CADDNOTEHOST        = 2026
    ADDNOTESRV          = 2027
    CADDNOTESRV         = 2028
    CADDNOTEVULN        = 2030
    CADDNOTEVULN        = 2031
    LOG                 = 2032
    DEVLOG              = 2033
    DELSERVICEINT       = 2034
    ADDCREDSRV       = 2035
    CADDCREDSRV      = 2036
    ADDVULNWEBSRV          = 2037
    CADDVULNWEBSRV         = 2038
    ADDNOTENOTE         = 2039
    CADDNOTENOTE        = 2039
    
    __descriptions = {
        ADDHOST             : "ADDHOST",
        CADDHOST            : "CADDHOST",
        ADDINTERFACE        : "ADDINTERFACE",
        CADDINTERFACE       : "CADDINTERFACE",
        ADDSERVICEINT       : "ADDSERVICEINT",
        ADDSERVICEAPP       : "ADDSERVICEAPP",
        CADDSERVICEINT      : "CADDSERVICEINT",
        CADDSERVICEAPP      : "CADDSERVICEAPP",
        CADDSERVICEHOST     : "CADDSERVICEHOST",
        ADDAPPLICATION      : "ADDAPPLICATION",
        CADDAPPLICATION     : "CADDAPPLICATION",
        ADDVULNINT          : "ADDVULNINT",
        CADDVULNINT         : "CADDVULNINT",
        ADDVULNAPP          : "ADDVULNAPP",
        CADDVULNAPP         : "CADDVULNAPP",
        ADDVULNHOST         : "ADDVULNHOST",
        CADDVULNHOST        : "CADDVULNHOST",
        ADDVULNSRV          : "ADDVULNSRV",
        CADDVULNSRV         : "CADDVULNSRV",
        LOG                 : "LOG",
        DEVLOG              : "DEVLOG",
        DELSERVICEINT       : "DELSERVICEINT",
        ADDCREDSRV       : "ADDCREDINT",
        ADDVULNWEBSRV          : "ADDVULNWEBSRV",
        CADDVULNWEBSRV         : "CADDVULNWEBSRV",
        ADDNOTENOTE          : "ADDNOTENOTE",
        CADDNOTENOTE         : "CADDNOTENOTE",
    }

    @staticmethod
    def getDescription(action):
        return modelactions.__descriptions.get(action, "")


class PluginControllerBase(object):
    """
    TODO: Doc string.
    """
    def __init__(self, id, available_plugins, mapper_manager):
        self._plugins               = available_plugins
        self.id                     = id
        self._actionDispatcher      = None
        self._setupActionDispatcher()

        self._mapper_manager = mapper_manager

    def _find_plugin(self, new_plugin_id):
        try:
            return self._plugins[new_plugin_id]
        except KeyError:
            return None

    def _is_command_malformed(self, original_command, modified_command):
        """
        Checks if the command to be executed is safe and it's not in the block list
        defined by the user. Returns False if the modified command is ok, True if
        otherwise.

        TODO: Use global command block list.
        TODO: complete block idioms
        """
        block_chars = set(["|", "$", "#"])

        if original_command == modified_command:
            return False

        orig_cmd_args = shlex.split(original_command)

        if not isinstance(modified_command, basestring):
            modified_command = ""
        mod_cmd_args = shlex.split(modified_command)

        block_flag = False
        orig_args_len = len(orig_cmd_args)
        for index in xrange(0, len(mod_cmd_args)):
            if index < orig_args_len and orig_cmd_args[index] == mod_cmd_args[index]:
                continue

            for char in block_chars:
                if char in mod_cmd_args[index]:
                    block_flag = True
                    break

        return block_flag

    def _get_plugins_by_input(self, current_input):
        """
        Finds a plugin that can parse the current input and returns the plugin
        object. Otherwise returns None.
        """
        for plugin in self._plugins.itervalues():
            if plugin.canParseCommandString(current_input):
                return plugin
        return None

    def getAvailablePlugins(self):
        """
        Return a dictionary with the available plugins.
        Plugin ID's as keys and plugin instences as values
        """
        return self._plugins

    def processOutput(self, plugin, output):
        output_queue = multiprocessing.JoinableQueue()
        new_elem_queue = multiprocessing.Queue()

        plugin_process = PluginProcess(plugin, output_queue, new_elem_queue)
        model.api.devlog("PluginController (%d) - Created plugin_process (%d) for plugin instance (%d)" %
                         (id(self), id(plugin_process), id(plugin)))

        plugin_process.start()

        output_queue.put(output)
        output_queue.put(None)
        output_queue.join()

        #model.api.devlog("Core: queue size '%s'" % new_elem_queue.qsize())
        while True:
            try:
                current_action = new_elem_queue.get(block=False)
                if current_action is None:
                    break
                action = current_action[0]
                parameters = current_action[1:]
                model.api.devlog("Core: Processing a new '%s' , parameters (%s) \n" % (action,str(parameters)))
                self._processAction(action, parameters)

            except Queue.Empty:
                continue
            except IOError, e:
                if e.errno == errno.EINTR:
                    continue
                else:
                    model.api.devlog("PluginController.onCommandFinished - new_elem_queue Exception- something strange happened... unhandled exception?")
                    model.api.devlog(traceback.format_exc())
                    break
            except Exception:
                model.api.devlog("PluginController.onCommandFinished - new_elem_queue Exception- something strange happened... unhandled exception?")
                model.api.devlog(traceback.format_exc())
                break

    def _processAction(self, action, parameters):
        """
        decodes and performs the action given
        It works kind of a dispatcher
        """
        model.api.devlog("(PluginController) _processAction - %s - parameters = %s" % (action, str(parameters)))
        res = self._actionDispatcher[action](*parameters)

    def _setupActionDispatcher(self):
        self._actionDispatcher = {
                    modelactions.ADDHOST : model.api.addHost,
                    modelactions.CADDHOST : model.api.createAndAddHost,
                    modelactions.ADDINTERFACE : model.api.addInterface,
                    modelactions.CADDINTERFACE : model.api.createAndAddInterface,
                    modelactions.ADDSERVICEINT : model.api.addServiceToInterface,
                    modelactions.ADDSERVICEAPP : model.api.addServiceToApplication,
                    modelactions.CADDSERVICEINT : model.api.createAndAddServiceToInterface,
                    modelactions.CADDSERVICEAPP : model.api.createAndAddServiceToApplication,
                    modelactions.ADDAPPLICATION : model.api.addApplication,
                    modelactions.CADDAPPLICATION :  model.api.createAndAddApplication,
                    modelactions.DELSERVICEINT : model.api.delServiceFromInterface,
                    #Vulnerability
                    modelactions.ADDVULNINT : model.api.addVulnToInterface,
                    modelactions.CADDVULNINT : model.api.createAndAddVulnToInterface,
                    modelactions.ADDVULNAPP : model.api.addVulnToApplication,
                    modelactions.CADDVULNAPP : model.api.createAndAddVulnToApplication,
                    modelactions.ADDVULNHOST : model.api.addVulnToHost,
                    modelactions.CADDVULNHOST : model.api.createAndAddVulnToHost,
                    modelactions.ADDVULNSRV : model.api.addVulnToService,
                    modelactions.CADDVULNSRV : model.api.createAndAddVulnToService,
                    #VulnWeb
                    modelactions.ADDVULNWEBSRV : model.api.addVulnWebToService,
                    modelactions.CADDVULNWEBSRV : model.api.createAndAddVulnWebToService,
                    #Note
                    modelactions.ADDNOTEINT : model.api.addNoteToInterface,
                    modelactions.CADDNOTEINT : model.api.createAndAddNoteToInterface,
                    modelactions.ADDNOTEAPP : model.api.addNoteToApplication,
                    modelactions.CADDNOTEAPP : model.api.createAndAddNoteToApplication,
                    modelactions.ADDNOTEHOST : model.api.addNoteToHost,
                    modelactions.CADDNOTEHOST : model.api.createAndAddNoteToHost,
                    modelactions.ADDNOTESRV : model.api.addNoteToService,
                    modelactions.CADDNOTESRV : model.api.createAndAddNoteToService,
                    modelactions.ADDNOTENOTE : model.api.addNoteToNote,
                    modelactions.CADDNOTENOTE : model.api.createAndAddNoteToNote,                    
                    #Creds
                    modelactions.CADDCREDSRV : model.api.createAndAddCredToService,
                    modelactions.ADDCREDSRV  :  model.api.addCredToService,
                    #modelactions.ADDNOTEVULN : model.api.createAndAddNoteToApplication,
                    #modelactions.CADDNOTEVULN : model.api.createAndAddNoteToApplication,
                    #LOG
                    modelactions.LOG : model.api.log,
                    modelactions.DEVLOG : model.api.devlog,
        }

    def updatePluginSettings(self, plugin_id, new_settings):
        if plugin_id in self._plugins:
            self._plugins[plugin_id].updateSettings(new_settings)


class PluginController(PluginControllerBase):
    """
    TODO: Doc string.
    """
    def __init__(self, id, available_plugins, mapper_manager):
        PluginControllerBase.__init__(self, id, available_plugins, mapper_manager)
        self._active_plugin = None
        self.last_command_information = None
        self._buffer = StringIO()

    def setActivePlugin(self, plugin):
        self._active_plugin = plugin

    def processCommandInput(self, prompt, username, current_path, command_string, interactive):
        """
        Receives the prompt that the current session has, the actual command_string that
        the user typed and if the command is interactive. If it is interactive the
        plugin controller does not choose a new active plugin but use the one the
        is already set (if none is set it raises an exeception).

        If always returns an string. It could be modified by the active plugin or, if
        there is none available, it will return the original command_string.
        """

        if interactive:
            return None
        else:
            self._disable_active_plugin()

        choosen_plugin = self._get_plugins_by_input(command_string)
        if choosen_plugin is None:
            model.api.devlog("There is no active plugin to handle current command/user input")
            return None
        self._active_plugin = choosen_plugin

        modified_cmd_string = self._active_plugin.processCommandString(
                                                                username,
                                                                current_path,
                                                                command_string)

        if self._is_command_malformed(command_string, modified_cmd_string):
            return None
        else:
            cmd_info = CommandRunInformation(
                **{'workspace': model.api.getActiveWorkspace().name,
                    'itime': time(),
                    'command': command_string.split()[0],
                    'params': ' '.join(command_string.split()[1:])})
            self._mapper_manager.save(cmd_info)

            self.last_command_information = cmd_info

            return modified_cmd_string if isinstance(modified_cmd_string, basestring) else None

    def storeCommandOutput(self, output):
        """
        Receives and output string and stores it in the buffer. Returns False
        if the output was not added to the plugin controllers buffer. Returns
        True otherwise.
        """
        if not self.getActivePluginStatus():
            return False
        else:
            self._buffer.write(output)
            return True

    def getPluginAutocompleteOptions(self, prompt, username, current_path, command_string, interactive):
        """
        This method should return a list of possible completitions based on the
        current output.
        TODO: We should think how to actually implement this...
        May be checking which plugin should handle the command in the current input
        and then passing it to the plugin to return a list of possible values.
        Each plugin implementation should return possible option according to
        what was received since it's the plugin the one it knows the command line
        parameters, etc.
        """
        if interactive:
            return None
        else:
            self._disable_active_plugin()

        choosen_plugin = self._get_plugins_by_input(command_string)
        if choosen_plugin is None:
            model.api.devlog("There is no active plugin to handle current command/user input")
            return None

        self._active_plugin = choosen_plugin

        new_options = self._active_plugin.getCompletitionSuggestionsList(command_string)
        return new_options

    def getActivePluginStatus(self):
        """
        Returns true if an active plugin is set, otherwise return False.
        """
        return (self._active_plugin is not None)

    def _disable_active_plugin(self):
        """
        This method is suppose to disable the active plugin.
        """
        model.api.devlog("Disabling active plugin")
        self._active_plugin = None

    def onCommandFinished(self):
        """
        This method is called when the last executed command has finished. It's
        in charge of giving the plugin the output to be parsed.
        """
        cmd_info = self.last_command_information
        cmd_info.duration = time() - cmd_info.itime
        self._mapper_manager.save(cmd_info)

        if self._active_plugin.has_custom_output():
            if not os.path.isfile(self._active_plugin.get_custom_file_path()):
                model.api.devlog("Report file PluginController output file (%s) not created" % self._active_plugin.get_custom_file_path())
                return False
            output_file = open(self._active_plugin.get_custom_file_path(), 'r')
            output = output_file.read()
            self._buffer.seek(0)
            self._buffer.truncate()
            self._buffer.write(output)

        self.processOutput(self._active_plugin, self._buffer.getvalue())

        self._buffer.seek(0)
        self._buffer.truncate()
        model.api.devlog("PluginController buffer cleared")

        self._disable_active_plugin()

        return True


class PluginControllerForApi(PluginControllerBase):
    def __init__(self, id, available_plugins, mapper_manager):
        PluginControllerBase.__init__(self, id, available_plugins, mapper_manager)
        self._active_plugins = {}

    def processCommandInput(self, command_string):

        plugin = self._get_plugins_by_input(command_string)

        if plugin:
            modified_cmd_string = plugin.processCommandString("", "", command_string)
            if not self._is_command_malformed(command_string, modified_cmd_string):

                cmd_info = CommandRunInformation(
                    **{'workspace': model.api.getActiveWorkspace().name,
                        'itime': time(),
                        'command': command_string.split()[0],
                        'params': ' '.join(command_string.split()[1:])})
                self._mapper_manager.save(cmd_info)

                self._active_plugins[command_string] = plugin, cmd_info

                output_file_path = None
                if plugin.has_custom_output():
                    output_file_path = plugin.get_custom_file_path()
                return True, modified_cmd_string, output_file_path

        return False, None, None

    def getPluginAutocompleteOptions(self, command_string):
        # if interactive:
        #     return None
        # else:
        #     self._disable_active_plugin()

        # choosen_plugin = self._get_plugins_by_input(command_string)
        # if choosen_plugin is None:
        #     model.api.devlog("There is no active plugin to handle current command/user input")
        #     return None

        # self._active_plugin = choosen_plugin

        # new_options = self._active_plugin.getCompletitionSuggestionsList(command_string)
        # return new_options
        pass

    def onCommandFinished(self, cmd, output):
        if cmd not in self._active_plugins.keys():
            return False

        plugin, cmd_info = self._active_plugins.get(cmd)
        cmd_info.duration = time() - cmd_info.itime
        self._mapper_manager.save(cmd_info)

        self.processOutput(plugin, output)

        del self._active_plugins[cmd]
        return True

    def clearActivePlugins(self):
        self._active_plugins = {}


class PluginBase(object):
    # TODO: Add class generic identifier
    class_signature = "PluginBase"

    def __init__(self):

        self.data_path = CONF.getDataPath()
        self.persistence_path = CONF.getPersistencePath()
        # Must be unique. Check that there is not
        # an existant plugin with the same id.
        # TODO: Make script that list current ids.
        self.id                = None
        self._rid              = id(self)
        self.version           = None
        self.name = None
        self.description = ""
        self._command_regex    = None
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
        return self._command_regex is not None and\
        self._command_regex.match(current_input.strip()) is not None
        
        
    def getCompletitionSuggestionsList(self, current_input):
        """
        This method can be overriden in the plugin implementation
        if a different kind of check is needed
        """
        
        words=current_input.split(" ")
        
        cword=words[len(words)-1] 
        
        
        
        options={}
        for k,v in self._completition.iteritems():
            if re.search(str("^"+cword),k,flags=re.IGNORECASE):
                
                options[k]=v
                
        return options

    def parseOutputString(self, output):
        """
        This method must be implemented.
        This method will be called when the command finished executing and
        the complete output will be received to work with it
        Using the output the plugin can create and add hosts, interfaces, services, etc.
        """
        pass

    def processCommandString(self, username, current_path, command_string):
        """
        With this method a plugin can add aditional arguments to the command that
        it's going to be executed.
        """
        return None 

    def getParsedElementsDict(self):
        """
        This method must be implemented and must return
        a dictionary with the following form.

        { 'FrameworkVersion': self.framework_version,
          'HostList': list_of_host_dictionaries,
          'PortList': list_of_port_dictionaries }

        list_of_host_dictionaries: must be 'None' or a list of
            dictionaries that have the following form

            { 'HostId': string,
              'HostAddress': string,
              ... }

        list_of_port_dictionaries: must be 'None' or a list of
            dictionaries that have the following form

            { 'PortNumber': integer,
              'Status': 'OPEN' or 'CLOSED',
              'Service': string,
              ... }
        """
        pass

    def _set_host(self):
        
        pass
        
    def __addPendingAction(self, *args):
        """
        Adds a new pending action to the queue
        Action is build with generic args tuple.
        The caller of this function has to build the action in the right
        way since no checks are preformed over args
        """
        self._pending_actions.put(args)

    def createAndAddHost(self, name, os = "unknown", category = None, update = False, old_hostname = None):
        self.__addPendingAction(modelactions.CADDHOST, name, os, category, update, old_hostname)
        return factory.generateID(Host.class_signature, name=name, os=os)

    def createAndAddInterface(self, host_id, name = "", mac = "00:00:00:00:00:00",
                 ipv4_address = "0.0.0.0", ipv4_mask = "0.0.0.0",
                 ipv4_gateway = "0.0.0.0", ipv4_dns = [],
                 ipv6_address = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_prefix = "00",
                 ipv6_gateway = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns = [],
                 network_segment = "", hostname_resolution = []):
        self.__addPendingAction(modelactions.CADDINTERFACE, host_id, name, mac, ipv4_address, 
            ipv4_mask, ipv4_gateway, ipv4_dns, ipv6_address, ipv6_prefix, ipv6_gateway, ipv6_dns,
            network_segment, hostname_resolution)
        return factory.generateID(
            Interface.class_signature, parent_id=host_id, name=name, mac=mac,
            ipv4_address=ipv4_address, ipv4_mask=ipv4_mask,
            ipv4_gateway=ipv4_gateway, ipv4_dns=ipv4_dns,
            ipv6_address=ipv6_address, ipv6_prefix=ipv6_prefix,
            ipv6_gateway=ipv6_gateway, ipv6_dns=ipv6_dns,
            network_segment=network_segment,
            hostname_resolution=hostname_resolution)

    def createAndAddServiceToInterface(self, host_id, interface_id, name, protocol = "tcp?", 
                ports = [], status = "running", version = "unknown", description = ""):
        self.__addPendingAction(modelactions.CADDSERVICEINT, host_id, interface_id, name, protocol, 
                ports, status, version, description)
        return factory.generateID(
            Service.class_signature,
            name=name, protocol=protocol, ports=ports,
            status=status, version=version, description=description, parent_id=interface_id)

    def createAndAddVulnToHost(self, host_id, name, desc="", ref=[], severity="", resolution=""):
        self.__addPendingAction(modelactions.CADDVULNHOST, host_id, name, desc, ref, severity, resolution)
        return factory.generateID(
            ModelObjectVuln.class_signature,
            name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, parent_id=host_id)

    def createAndAddVulnToInterface(self, host_id, interface_id, name, desc="", ref=[], severity="", resolution=""):
        self.__addPendingAction(modelactions.CADDVULNINT, host_id, interface_id, name, desc, ref, severity, resolution)
        return factory.generateID(
            ModelObjectVuln.class_signature,
            name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, parent_id=interface_id)

    def createAndAddVulnToService(self, host_id, service_id, name, desc="", ref=[], severity="", resolution=""):
        self.__addPendingAction(modelactions.CADDVULNSRV, host_id, service_id, name, desc, ref, severity, resolution)
        return factory.generateID(
            ModelObjectVuln.class_signature,
            name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, parent_id=service_id)

    def createAndAddVulnWebToService(self, host_id, service_id, name, desc="", ref=[],
                                    severity="", resolution="", website="", path="", request="",
                                    response="",method="",pname="", params="",query="",category=""):
        self.__addPendingAction(modelactions.CADDVULNWEBSRV, host_id, service_id, name, desc, ref,
                                severity, resolution, website, path, request, response,
                                method, pname, params, query,category)
        return factory.generateID(
            ModelObjectVulnWeb.class_signature,
            name=name, desc=desc, ref=ref, severity=severity, resolution=resolution, 
            website=website, path=path, request=request, response=response,
            method=method, pname=pname, params=params, query=query,
            category=category, parent_id=service_id)

    def createAndAddNoteToHost(self, host_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTEHOST, host_id, name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=host_id)

    def createAndAddNoteToInterface(self, host_id, interface_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTEINT, host_id, interface_id, name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=interface_id)

    def createAndAddNoteToService(self, host_id, service_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTESRV, host_id, service_id, name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=service_id)

    def createAndAddNoteToNote(self, host_id, service_id, note_id, name, text):
        self.__addPendingAction(modelactions.CADDNOTENOTE, host_id, service_id, note_id, name, text)
        return factory.generateID(
            ModelObjectNote.class_signature,
            name=name, text=text, parent_id=note_id)

    def createAndAddCredToService(self, host_id, service_id, username, password):
        self.__addPendingAction(modelactions.CADDCREDSRV, host_id, service_id, username, password)
        return factory.generateID(
            ModelObjectCred.class_signature,
            username=username, password=password, parent_id=service_id)

    def addHost(self, host, category=None,update=False, old_hostname=None):
        self.__addPendingAction(modelactions.ADDHOST, host, category, update, old_hostname)

    def addInterface(self, host_id, interface):
        self.__addPendingAction(modelactions.ADDINTERFACE, host_id, interface)

    def addApplication(self, host_id, application):
        self.__addPendingAction(modelactions.ADDAPPLICATION, host_id, application)

    def addServiceToApplication(self, host_id, application_id, service):
        self.__addPendingAction(modelactions.ADDSERVICEAPP, host_id, application_id, service)

    def addServiceToInterface(self, host_id, interface_id, service):
        self.__addPendingAction(modelactions.ADDSERVICEINT, host_id, interface_id, service)

    def addVulnToHost(self, host_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNHOST, host_id, vuln)

    def addVulnToInterface(self, host_id, interface_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNINT, host_id, interface_id, vuln)

    def addVulnToApplication(self, host_id, application_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNAPP, host_id, application_id, vuln)

    def addVulnToService(self, host_id, service_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNSRV, host_id, service_id, vuln)

    def addVulnWebToService(self, host_id, service_id, vuln):
        self.__addPendingAction(modelactions.ADDVULNWEBSRV, host_id, service_id, vuln)
        
    def addNoteToHost(self, host_id, note):
        self.__addPendingAction(modelactions.ADDNOTEHOST, host_id, note)

    def addNoteToInterface(self, host_id, interface_id, note):
        self.__addPendingAction(modelactions.ADDNOTEINT, host_id, interface_id, note)

    def addNoteToApplication(self, host_id, application_id, note):
        self.__addPendingAction(modelactions.ADDNOTEAPP, host_id, application_id, note)

    def addNoteToService(self, host_id, service_id, note):
        self.__addPendingAction(modelactions.ADDNOTESRV, host_id, service_id, note)

    def addNoteToNote(self, host_id, service_id,note_id, note):
        self.__addPendingAction(modelactions.ADDNOTENOTE, host_id, service_id, note_id, note)
        
    def addCredToService(self, host_id, service_id, cred):
        self.__addPendingAction(modelactions.ADDCREDSRV, host_id, service_id, cred)

    def delServiceFromInterface(self, service, hostname,
                 intname, remote = True):
        self.__addPendingAction(modelactions.DELSERVICEINT,hostname,intname,service,remote)
        
    def log(self, msg, level='INFO'):
        self.__addPendingAction(modelactions.LOG,msg,level)

    def devlog(self, msg):        
        self.__addPendingAction(modelactions.DEVLOG,msg)


class PluginProcess(multiprocessing.Process):
    def __init__(self, plugin_instance, output_queue, new_elem_queue):
        multiprocessing.Process.__init__(self)
        self.output_queue = output_queue
        self.new_elem_queue = new_elem_queue
        self.plugin = plugin_instance
        

    def run(self):
        proc_name = self.name
        plugin = self.plugin
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
                    self.output = output
                    self.plugin.parseOutputString(output)
                except Exception as e:
                    print  ('Plugin Error: %s, (%s)' % (plugin.id, sha1OfStr(output)))
                    model.api.log('Plugin Error: %s, (%s)' % (plugin.id, sha1OfStr(output)),"DEBUG")
                    model.api.devlog("Plugin raised an exception:")
                    model.api.devlog(traceback.format_exc())
                else:
                    while True:
                        try:
                            self.new_elem_queue.put(self.plugin._pending_actions.get(block=False))
                        except Queue.Empty:
                            model.api.log('Plugin Error: %s, (%s)' % (plugin.id, sha1OfStr(output)),"DEBUG")
                            model.api.devlog("PluginProcess run _pending_actions queue Empty. Breaking loop")
                            break
                        except Exception:
                            model.api.log('Plugin Error: %s, (%s)' % (plugin.id, sha1OfStr(output)),"DEBUG")
                            model.api.devlog("PluginProcess run getting from _pending_action queue - something strange happened... unhandled exception?")
                            model.api.devlog(traceback.format_exc())
                            break

            else:
                
                done = True
                model.api.devlog('%s: Exiting' % proc_name)
                model.api.log('Plugin finished: %s, (%s)' % (plugin.id, sha1OfStr(self.output)),"DEBUG")
                print  ('Plugin finished: %s, (%s)' % (plugin.id, sha1OfStr(self.output)))
                
            self.output_queue.task_done()
        self.new_elem_queue.put(None)
        return

