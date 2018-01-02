#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import threading

import os
import time
import Queue
import shlex
import errno
import logging
from multiprocessing import JoinableQueue
from Queue import Queue, Empty

from plugins.plugin import PluginProcess
import model.api
from model.commands_history import CommandRunInformation
from model.controller import modelactions
from utils.logs import getLogger

from config.globals import (
    CONST_FARADAY_HOME_PATH,
    CONST_FARADAY_ZSH_OUTPUT_PATH)

logger = logging.getLogger(__name__)


class PluginController(threading.Thread):
    """
    TODO: Doc string.
    """
    def __init__(self, id, plugin_manager, mapper_manager, pending_actions):
        super(PluginController, self).__init__()
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
        self.stop = False
        self.pending_actions = pending_actions

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

    def stop(self):
        self.stop = True

    def processOutput(self, plugin, output, command_id, isReport=False):
        output_queue = JoinableQueue()
        plugin.set_actions_queue(self.pending_actions)

        plugin_process = PluginProcess(
            plugin, output_queue, isReport)

        getLogger(self).debug(
            "Created plugin_process (%d) for plugin instance (%d)" %
            (id(plugin_process), id(plugin)))

        # TODO: stop this processes
        plugin_process.start()

        print('Plugin controller ', self.pending_actions)
        self.pending_actions.put((modelactions.PLUGINSTART, plugin.id, command_id))

        output_queue.put((output, command_id))
        output_queue.join()

        self.pending_actions.put((modelactions.PLUGINEND, plugin.id, command_id))

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
            modelactions.ADDSERVICEHOST: model.api.addServiceToHost,
            #Vulnerability
            modelactions.ADDVULNHOST: model.api.addVulnToHost,
            modelactions.ADDVULNSRV: model.api.addVulnToService,
            #VulnWeb
            modelactions.ADDVULNWEBSRV: model.api.addVulnWebToService,
            #Note
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

        self.processOutput(plugin, term_output, cmd_info.getID())
        del self._active_plugins[pid]
        return True

    def processReport(self, plugin, filepath, ws_name=None):
        if not ws_name:
            ws_name = model.api.getActiveWorkspace().name
        cmd_info = CommandRunInformation(
            **{'workspace': ws_name,
                'itime': time.time(),
                'command': 'Import %s:' % plugin,
                'params': filepath})
        self._mapper_manager.createMappers(ws_name)
        cmd_info.setID(self._mapper_manager.save(cmd_info))

        if plugin in self._plugins:
            logger.info('Processing report with plugin {0}'.format(plugin))
            self.processOutput(self._plugins[plugin], filepath, cmd_info.getID(), True)
            cmd_info.duration = time.time() - cmd_info.itime
            self._mapper_manager.update(cmd_info)
            return True
        return False

    def clearActivePlugins(self):
        self._active_plugins = {}
