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


class PluginController(object):
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
        self._active_plugins = {}
        self.plugin_sets = {}
        self.plugin_manager.addController(self, self.id)

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

    def _get_plugins_by_input(self, cmd, plugin_set):
        for plugin in plugin_set.itervalues():
            if plugin.canParseCommandString(cmd):
                return plugin
        return None

    def getAvailablePlugins(self):
        """
        Return a dictionary with the available plugins.
        Plugin ID's as keys and plugin instences as values
        """
        return self._plugins

    def processOutput(self, plugin, output, command_id, isReport=False):
        output_queue = multiprocessing.JoinableQueue()
        new_elem_queue = multiprocessing.Queue()

        plugin_process = PluginProcess(
            plugin, output_queue, new_elem_queue, isReport)

        getLogger(self).debug(
            "Created plugin_process (%d) for plugin instance (%d)" %
            (id(plugin_process), id(plugin)))

        plugin_process.start()

        output_queue.put(output)
        output_queue.put(None)
        output_queue.join()

        self._processAction(modelactions.PLUGINSTART, [plugin.id])

        while True:
            try:
                current_action = new_elem_queue.get(block=False)
                if current_action is None:
                    break
                action = current_action[0]
                parameters = current_action[1:]

                if hasattr(parameters[-1], '_metadata'):
                    parameters[-1]._metadata.command_id = command_id

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
        self._processAction(modelactions.PLUGINEND, [plugin.id])

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
            modelactions.ADDINTERFACE: model.api.addInterface,
            modelactions.ADDSERVICEINT: model.api.addServiceToInterface,
            modelactions.DELSERVICEINT: model.api.delServiceFromInterface,
            #Vulnerability
            modelactions.ADDVULNINT: model.api.addVulnToInterface,
            modelactions.ADDVULNHOST: model.api.addVulnToHost,
            modelactions.ADDVULNSRV: model.api.addVulnToService,
            #VulnWeb
            modelactions.ADDVULNWEBSRV: model.api.addVulnWebToService,
            #Note
            modelactions.ADDNOTEINT: model.api.addNoteToInterface,
            modelactions.ADDNOTEHOST: model.api.addNoteToHost,
            modelactions.ADDNOTESRV: model.api.addNoteToService,
            modelactions.ADDNOTENOTE: model.api.addNoteToNote,
            #Creds
            modelactions.ADDCREDSRV:  model.api.addCredToService,
            #LOG
            modelactions.LOG: model.api.log,
            modelactions.DEVLOG: model.api.devlog,
            # Plugin state
            modelactions.PLUGINSTART: model.api.pluginStart,
            modelactions.PLUGINEND: model.api.pluginEnd
        }

    def updatePluginSettings(self, plugin_id, new_settings):
        for plugin_set in self.plugin_sets.values():
            if plugin_id in plugin_set:
                plugin_set[plugin_id].updateSettings(new_settings)
        if plugin_id in self._plugins:
            self._plugins[plugin_id].updateSettings(new_settings)

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

    def onCommandFinished(self, pid, exit_code, term_output):

        if pid not in self._active_plugins.keys():
            return False
        if exit_code != 0:
            del self._active_plugins[pid]
            return False

        plugin, cmd_info = self._active_plugins.get(pid)

        cmd_info.duration = time.time() - cmd_info.itime
        self._mapper_manager.update(cmd_info)

        self.processOutput(plugin, term_output, cmd_info.getID()
)
        del self._active_plugins[pid]
        return True

    def processReport(self, plugin, filepath):

        cmd_info = CommandRunInformation(
            **{'workspace': model.api.getActiveWorkspace().name,
                'itime': time.time(),
                'command': 'Import %s:' % plugin,
                'params': filepath})
        self._mapper_manager.save(cmd_info)

        if plugin in self._plugins:
            self.processOutput(self._plugins[plugin], filepath, cmd_info.getID(), True )
            cmd_info.duration = time.time() - cmd_info.itime
            self._mapper_manager.update(cmd_info)
            return True
        return False

    def clearActivePlugins(self):
        self._active_plugins = {}
