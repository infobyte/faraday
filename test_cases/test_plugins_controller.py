import sys
sys.path.append('.')
import unittest
from Queue import Queue
from mock import MagicMock as mock

import plugins.controller


class PluginControllerUnitTest(unittest.TestCase):

    def setUp(self):

        def create_not_plugin(name, can_parse_command_string):
            plugin = mock()
            plugin.canParseCommandString = mock(return_value=can_parse_command_string)
            plugin.updateSettings = mock()
            plugin.name = name
            plugin.processCommandString = mock(return_value='modified cmd string')
            return plugin

        def create_not_plugin_manager():
            not_plugin_manager = mock()
            self.plugin1 = create_not_plugin('plugin1', True)
            self.plugin2 = create_not_plugin('plugin2', False)
            self.plugin3 = create_not_plugin('plugin3', False)
            self.plugin4 = create_not_plugin('plugin4', False)
            not_plugin_manager.getPlugins = mock(return_value={'plugin1': self.plugin1,
                                                                 'plugin2': self.plugin2,
                                                                 'plugin3': self.plugin3,
                                                                 'plugin4': self.plugin4})
            return not_plugin_manager

        def create_not_mappers_manager():
            not_mappers_manager = mock()

        self.pending_actions = Queue()
        self.not_plugin_manager = create_not_plugin_manager()
        self.not_mappers_manager = create_not_mappers_manager()
        self.controller = plugins.controller.PluginController('PluginController',
                                                              self.not_plugin_manager,
                                                              self.not_mappers_manager,
                                                              self.pending_actions)

    def test_find_plugin_that_exists(self):
        plugin = self.controller._find_plugin('plugin1')
        self.assertEqual(plugin.name, 'plugin1')

    def test_find_plugin_that_doesnt_exist(self):
        plugin = self.controller._find_plugin('key_non_existant')
        self.assertIs(plugin, None)

    def test_command_malformed(self):
        blocked_with_pipe = self.controller._is_command_malformed("test --command", "test --command | tee test")
        blocked_with_dollar = self.controller._is_command_malformed("test --command", "test --command $HOLA")
        blocked_with_hash = self.controller._is_command_malformed("test --command", "test # --command ")
        self.assertEqual(blocked_with_pipe, True)
        self.assertEqual(blocked_with_dollar, True)
        self.assertEqual(blocked_with_hash, True)

    def test_command_not_malformed(self):
        nice_command_blocked = self.controller._is_command_malformed("test --command", "test --command wush")
        self.assertEqual(nice_command_blocked, False)

    def test_getting_plugins_by_input_that_can_parse_cmd(self):
        plugin_set = {
            '1': self.plugin1,
            '2': self.plugin2,
            '3': self.plugin3,
            '4': self.plugin4}
        should_be_plugin_1 = self.controller._get_plugins_by_input('ping', plugin_set)
        self.assertIs(should_be_plugin_1, self.plugin1)

    def test_return_none_when_cant_find_plugin_that_can_parse_cmd(self):
        plugin_set = {
            '2': self.plugin2,
            '3': self.plugin3,
            '4': self.plugin4}
        should_be_none = self.controller._get_plugins_by_input('ping', plugin_set)
        self.assertIs(should_be_none, None)

    def test_update_plugin_settings(self):
        plugin_id = 'plugin1'
        new_settings = {'setting1': 'value1', 'setting2': 'value2'}
        self.controller.updatePluginSettings(plugin_id, new_settings)
        self.plugin1.updateSettings.assert_called_once_with(new_settings)

    def test_update_plugin_settings_with_no_settings(self):
        plugin_id = 'plugin1'
        new_settings = {}
        self.controller.updatePluginSettings(plugin_id, new_settings)
        self.plugin1.updateSettings.assert_called_once_with(new_settings)
