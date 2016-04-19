#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import errno
from cStringIO import StringIO
import multiprocessing
import os
import Queue
import shlex
import time

from plugins.plugin import PluginProcess
import model.api
from model.commands_history import CommandRunInformation
from plugins.modelactions import modelactions
from utils.logs import getLogger

from config.globals import (
    CONST_FARADAY_HOME_PATH,
    CONST_FARADAY_ZSH_OUTPUT_PATH)


class PluginControllerBase(object):
    """
    TODO: Doc string.
    """
    def __init__(self, id, plugin_manager, mapper_manager):
        self.plugin_manager = plugin_manager
        self._plugins = plugin_manager.getPlugins()
        self.id = id
        self._actionDispatcher = None
        self._setupActionDispatcher()
        self._mapper_manager = mapper_manager
        self.output_path = os.path.join(
            os.path.expanduser(CONST_FARADAY_HOME_PATH),
            CONST_FARADAY_ZSH_OUTPUT_PATH)

    def _find_plugin(self, plugin_id):
        return self._plugins.get(plugin_id, None)

    def _is_command_malformed(self, original_command, modified_command):
        """
        Checks if the command to be executed is safe and it's not in the
        block list defined by the user. Returns False if the modified
        command is ok, True if otherwise.
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
            if (index < orig_args_len and
                    orig_cmd_args[index] == mod_cmd_args[index]):
                continue

            for char in block_chars:
                if char in mod_cmd_args[index]:
                    block_flag = True
                    break

        return block_flag

    def _get_plugins_by_input(self, current_input):
        """
        Finds a plugin that can parse the current input and returns
        the plugin object. Otherwise returns None.
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
        getLogger(self).debug(
            "Created plugin_process (%d) for plugin instance (%d)" %
            (id(plugin_process), id(plugin)))

        plugin_process.start()

        output_queue.put(output)
        output_queue.put(None)
        output_queue.join()

        self._processAction(modelactions.PLUGINSTART, [])

        while True:
            try:
                current_action = new_elem_queue.get(block=False)
                if current_action is None:
                    break
                action = current_action[0]
                parameters = current_action[1:]
                getLogger(self).debug(
                    "Core: Processing a new '%s', parameters (%s)\n" %
                    (action, str(parameters)))
                self._processAction(action, parameters)

            except Queue.Empty:
                continue
            except IOError, e:
                if e.errno == errno.EINTR:
                    continue
                else:
                    getLogger(self).debug(
                        "new_elem_queue Exception - "
                        "something strange happened... "
                        "unhandled exception?")
                    break
            except Exception:
                getLogger(self).debug(
                    "new_elem_queue Exception - "
                    "something strange happened... "
                    "unhandled exception?")
                break
        self._processAction(modelactions.PLUGINEND, [])

    def _processAction(self, action, parameters):
        """
        decodes and performs the action given
        It works kind of a dispatcher
        """
        getLogger(self).debug(
            "_processAction - %s - parameters = %s" %
            (action, str(parameters)))
        self._actionDispatcher[action](*parameters)

    def _setupActionDispatcher(self):
        self._actionDispatcher = {
            modelactions.ADDHOST: model.api.addHost,
            modelactions.CADDHOST: model.api.createAndAddHost,
            modelactions.ADDINTERFACE: model.api.addInterface,
            modelactions.CADDINTERFACE: model.api.createAndAddInterface,
            modelactions.ADDSERVICEINT: model.api.addServiceToInterface,
            modelactions.ADDSERVICEAPP: model.api.addServiceToApplication,
            modelactions.CADDSERVICEINT: model.api.createAndAddServiceToInterface,
            modelactions.CADDSERVICEAPP: model.api.createAndAddServiceToApplication,
            modelactions.ADDAPPLICATION: model.api.addApplication,
            modelactions.CADDAPPLICATION:  model.api.createAndAddApplication,
            modelactions.DELSERVICEINT: model.api.delServiceFromInterface,
            #Vulnerability
            modelactions.ADDVULNINT: model.api.addVulnToInterface,
            modelactions.CADDVULNINT: model.api.createAndAddVulnToInterface,
            modelactions.ADDVULNAPP: model.api.addVulnToApplication,
            modelactions.CADDVULNAPP: model.api.createAndAddVulnToApplication,
            modelactions.ADDVULNHOST: model.api.addVulnToHost,
            modelactions.CADDVULNHOST: model.api.createAndAddVulnToHost,
            modelactions.ADDVULNSRV: model.api.addVulnToService,
            modelactions.CADDVULNSRV: model.api.createAndAddVulnToService,
            #VulnWeb
            modelactions.ADDVULNWEBSRV: model.api.addVulnWebToService,
            modelactions.CADDVULNWEBSRV: model.api.createAndAddVulnWebToService,
            #Note
            modelactions.ADDNOTEINT: model.api.addNoteToInterface,
            modelactions.CADDNOTEINT: model.api.createAndAddNoteToInterface,
            modelactions.ADDNOTEAPP: model.api.addNoteToApplication,
            modelactions.CADDNOTEAPP: model.api.createAndAddNoteToApplication,
            modelactions.ADDNOTEHOST: model.api.addNoteToHost,
            modelactions.CADDNOTEHOST: model.api.createAndAddNoteToHost,
            modelactions.ADDNOTESRV: model.api.addNoteToService,
            modelactions.CADDNOTESRV: model.api.createAndAddNoteToService,
            modelactions.ADDNOTENOTE: model.api.addNoteToNote,
            modelactions.CADDNOTENOTE: model.api.createAndAddNoteToNote,
            #Creds
            modelactions.CADDCREDSRV: model.api.createAndAddCredToService,
            modelactions.ADDCREDSRV:  model.api.addCredToService,
            #LOG
            modelactions.LOG: model.api.log,
            modelactions.DEVLOG: model.api.devlog,
            # Plugin state
            modelactions.PLUGINSTART: model.api.pluginStart,
            modelactions.PLUGINEND: model.api.pluginEnd
        }

    def updatePluginSettings(self, plugin_id, new_settings):
        if plugin_id in self._plugins:
            self._plugins[plugin_id].updateSettings(new_settings)


class PluginController(PluginControllerBase):
    """
    This class is going to be deprecated once we dump qt3
    """
    def __init__(self, id, plugin_manager, mapper_manager):
        PluginControllerBase.__init__(self, id, plugin_manager, mapper_manager)
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
                    'itime': time.time(),
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
        cmd_info.duration = time.time() - cmd_info.itime
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
    def __init__(self, id, plugin_manager, mapper_manager):
        PluginControllerBase.__init__(
            self, id, plugin_manager, mapper_manager)
        self._active_plugins = {}
        self.plugin_sets = {}
        self.plugin_manager.addController(self, self.id)

    def _get_plugins_by_input(self, cmd, plugin_set):
        for plugin in plugin_set.itervalues():
            if plugin.canParseCommandString(cmd):
                return plugin
        return None

    def createPluginSet(self, id):
        self.plugin_sets[id] = self.plugin_manager.getPlugins()

    def processCommandInput(self, pid, cmd, pwd):
        """
        This method tries to find a plugin to parse the command sent
        by the terminal (identiefied by the process id).
        """
        if pid not in self.plugin_sets:
            self.createPluginSet(pid)

        plugin = self._get_plugins_by_input(cmd, self.plugin_sets[pid])

        if plugin:
            modified_cmd_string = plugin.processCommandString("", pwd, cmd)
            if not self._is_command_malformed(cmd, modified_cmd_string):

                cmd_info = CommandRunInformation(
                    **{'workspace': model.api.getActiveWorkspace().name,
                        'itime': time.time(),
                        'command': cmd.split()[0],
                        'params': ' '.join(cmd.split()[1:])})
                self._mapper_manager.save(cmd_info)
                self._active_plugins[pid] = plugin, cmd_info

                return plugin.id, modified_cmd_string

        return None, None

    def getPluginAutocompleteOptions(self, command_string):
        """
        Not implementend right now. Maybe it's better to use
        zsh autocomplete features
        """
        pass

    def onCommandFinished(self, pid, exit_code, term_output):

        if pid not in self._active_plugins.keys():
            return False
        if exit_code != 0:
            del self._active_plugins[pid]
            return False

        plugin, cmd_info = self._active_plugins.get(pid)

        cmd_info.duration = time.time() - cmd_info.itime
        self._mapper_manager.save(cmd_info)

        self.processOutput(plugin, term_output)
        del self._active_plugins[pid]
        return True

    def processReport(self, plugin, filepath):
        if plugin in self._plugins:
            plugin.processReport(filepath)
            return True
        return False

    def clearActivePlugins(self):
        self._active_plugins = {}

    def updatePluginSettings(self, plugin_id, new_settings):
        for plugin_set in self.plugin_sets.values():
            if plugin_id in plugin_set:
                plugin_set[plugin_id].updateSettings(new_settings)
        if plugin_id in self._plugins:
            self._plugins[plugin_id].updateSettings(new_settings)
