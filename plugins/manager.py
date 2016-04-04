#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import imp
import os
import re
import sys
import traceback

import plugins.core
from config.configuration import getInstanceConfiguration
from utils.logs import getLogger

CONF = getInstanceConfiguration()


class PluginManager(object):
    def __init__(self, plugin_repo_path, mapper_manager):
        self._controllers = {}
        self._plugin_modules = {}
        self._loadPlugins(plugin_repo_path)
        self._mapper_manager = mapper_manager

        self._plugin_settings = {}
        self._loadSettings()

    def createController(self, id):
        """
        Creates a new plugin controller and adds it into the controllers list.
        """
        plugs = self._instancePlugins()
        new_controller = plugins.core.PluginController(
            id, plugs, self._mapper_manager)
        self._controllers[new_controller.id] = new_controller
        self.updateSettings(self._plugin_settings)
        return new_controller

    def _loadSettings(self):
        _plugin_settings = CONF.getPluginSettings()
        if _plugin_settings:

            self._plugin_settings = _plugin_settings

        activep = self._instancePlugins()
        for plugin_id, plugin in activep.iteritems():

            if plugin_id not in _plugin_settings:
                self._plugin_settings[plugin_id] = {
                    "name": plugin.name,
                    "description": plugin.description,
                    "version": plugin.version,
                    "plugin_version": plugin.plugin_version,
                    "settings": dict(plugin.getSettings())
                    }

        dplugins = []
        for k, v in self._plugin_settings.iteritems():
            if k not in activep:
                dplugins.append(k)

        for d in dplugins:
            del self._plugin_settings[d]

        CONF.setPluginSettings(self._plugin_settings)
        CONF.saveConfig()

    def getSettings(self):
        return self._plugin_settings

    def updateSettings(self, settings):
        self._plugin_settings = settings
        CONF.setPluginSettings(settings)
        CONF.saveConfig()
        for plugin_id, params in settings.iteritems():
            new_settings = params["settings"]
            for c_id, c_instance in self._controllers.iteritems():
                c_instance.updatePluginSettings(plugin_id, new_settings)

    def _instancePlugins(self):
        plugins = {}
        for module in self._plugin_modules.itervalues():
            new_plugin = module.createPlugin()
            self._verifyPlugin(new_plugin)
            plugins[new_plugin.id] = new_plugin
        return plugins

    def _loadPlugins(self, plugin_repo_path):
        """
        Finds and load all the plugins that are
        available in the plugin_repo_path.
        """
        try:
            os.stat(plugin_repo_path)
        except OSError:

            pass

        sys.path.append(plugin_repo_path)

        dir_name_regexp = re.compile(r"^[\d\w\-\_]+$")
        for name in os.listdir(plugin_repo_path):
            if dir_name_regexp.match(name):
                try:
                    module_path = os.path.join(plugin_repo_path, name)
                    sys.path.append(module_path)
                    module_filename = os.path.join(module_path, "plugin.py")
                    self._plugin_modules[name] = imp.load_source(
                        name, module_filename)
                except Exception as e:
                    msg = "An error ocurred while loading plugin %s.\n%s" % (
                        module_filename, traceback.format_exc())
                    getLogger(self).debug(msg)
                    getLogger(self).warn(e)
            else:
                pass

    def getPlugins(self):
        return self._instancePlugins()

    def _updatePluginSettings(self, new_plugin_id):
        pass

    def _verifyPlugin(self, new_plugin):
        """
        Generic method that decides is a plugin is valid
        based on a predefined set of checks.
        """
        try:
            assert(new_plugin.id is not None)
            assert(new_plugin.version is not None)
            assert(new_plugin.name is not None)
            assert(new_plugin.framework_version is not None)
        except (AssertionError, KeyError):

            return False
        return True
