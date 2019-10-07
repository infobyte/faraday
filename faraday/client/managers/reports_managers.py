"""
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import json
import os
import re
import time
import traceback
import logging

from random import random
from threading import Thread, Timer

from faraday.config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

logger = logging.getLogger(__name__)

try:
    import xml.etree.cElementTree as ET
except ImportError:
    print("cElementTree could not be imported. Using ElementTree instead")
    import xml.etree.ElementTree as ET


class OnlinePlugins(Thread):

    def __init__(self, plugin_controller):

        Thread.__init__(self, name="OnlinePluginsThread")
        self.setDaemon(True)
        self._must_stop = False

        self.online_plugins = {
            "MetasploitOn": {
                "time": 30,
                "command": "./metasploiton online"},
            "Beef": {
                "time": 30,
                "command": "./beef online"},
            "Sentinel": {
                "time": 60,
                "command": "sentinel"}
        }

        self.plugins_settings = CONF.getPluginSettings()
        self.plugin_controller = plugin_controller

    def runPluginThread(self, cmd):
        random_id = random()
        self.plugin_controller.processCommandInput(random_id, cmd, './')
        self.plugin_controller.onCommandFinished(random_id, 0, cmd)
        logger.debug("Running online plugin...")

    def stop(self):
        self._must_stop = True

    def run(self):

        while not self._must_stop:

            for name, config_dict in self.online_plugins.items():
                if name in self.plugins_settings:
                    if self.plugins_settings[name]['settings']['Enable'] == "1":

                        t = Timer(
                            config_dict["time"],
                            self.runPluginThread, args=(config_dict["command"],))

                        logger.debug(
                            "Starting Thread for online plugin: %s" % name)

                        self.online_plugins[name]["thread_running"] = True
                        t.start()

            time.sleep(60)


class ReportProcessor:

    def __init__(self, plugin_controller, ws_name=None):
        self.plugin_controller = plugin_controller
        self.ws_name = ws_name

    def processReport(self, filename):
        """ Process one Report """
        logger.debug("Report file is %s" % filename)
        report_analyzer = ReportAnalyzer(self.plugin_controller, filename)
        plugin_id = report_analyzer.get_plugin_id()
        if not plugin_id:
            logger.error('Plugin not found: automatic and manual try!')
            return None
        return self.sendReport(plugin_id, filename)

    def sendReport(self, plugin_id, filename):
        """Sends a report to the appropiate plugin specified by plugin_id"""
        logger.info('The file is %s, %s', filename, plugin_id)
        command_id = self.plugin_controller.processReport(plugin_id, filename, ws_name=self.ws_name)
        if not command_id:
            logger.error("Faraday doesn't have a plugin for this tool... Processing: ABORT")
            return None
        return command_id


class ReportManager(Thread):

    def __init__(self, timer, ws_name, plugin_controller, polling=True):
        Thread.__init__(self)
        self.setDaemon(True)
        self.polling = polling
        self.ws_name = ws_name
        self.timer = timer
        self._must_stop = False
        self._report_path = os.path.join(CONF.getReportPath(), ws_name)
        self._report_ppath = os.path.join(self._report_path, "process")
        self._report_upath = os.path.join(self._report_path, "unprocessed")
        self.processor = ReportProcessor(plugin_controller, ws_name)
        self.online_plugins = OnlinePlugins(plugin_controller)
        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)
        if not os.path.exists(self._report_ppath):
            os.mkdir(self._report_ppath)
        if not os.path.exists(self._report_upath):
            os.mkdir(self._report_upath)

    def run(self):
        self.online_plugins.start()
        tmp_timer = .0
        while not self._must_stop:
            time.sleep(.1)
            tmp_timer += .1
            if tmp_timer >= self.timer:
                try:
                    self.syncReports()
                    if not self.polling:
                        break
                except Exception:
                    logger.error("An exception was captured while saving reports\n%s", traceback.format_exc())
                finally:
                    tmp_timer = 0

    def stop(self):
        self._must_stop = True
        self.online_plugins.stop()

    def syncReports(self):
        """
        Synchronize report directory using the DataManager and Plugins online
        We first make sure that all shared reports were added to the repo
        """
        for root, dirs, files in os.walk(self._report_path, False):
            # skip processed and unprocessed directories
            if root == self._report_path:
                for name in files:
                    filename = os.path.join(root, name)
                    name = os.path.basename(filename)
                    # If plugin not is detected... move to unprocessed
                    # PluginCommiter will rename the file to processed or unprocessed
                    # when the plugin finishes
                    if self.processor.processReport(filename) is False:
                        logger.info('Plugin not detected. Moving {0} to unprocessed'.format(filename))
                        os.rename(filename, os.path.join(self._report_upath, name))
                    else:
                        logger.info("Detected valid report {%s}", filename)
                        os.rename(filename, os.path.join(self._report_ppath, name))

    def sendReportToPluginById(self, plugin_id, filename):
        """Sends a report to be processed by the specified plugin_id"""
        self.processor.sendReport(plugin_id, filename)


class ReportAnalyzer:

    def __init__(self, plugin_controller, report_path):
        self.plugin_controller = plugin_controller
        self.report_path = report_path

    def get_plugin_id(self):
        if not os.path.isfile(self.report_path):
            logger.error("Report [%s] don't exists", self.report_path)
            return None
        else:
            file_name = os.path.basename(self.report_path)
            plugin_id = self._get_plugin_by_name(file_name)
            if not plugin_id:   # Was unable to detect plugin from report file name
                logger.debug("Plugin by name not found")
                plugin_id = self._get_plugin_by_file_type(self.report_path)
                if not plugin_id:
                    logger.debug("Plugin by file not found")
            return plugin_id

    def _get_plugin_by_file_type(self, report_path):
        plugin_id = None
        file_name = os.path.basename(self.report_path)
        file_name_base, file_extension = os.path.splitext(file_name)
        file_extension = file_extension.lower()
        main_tag = None
        logger.debug("Analyze report File")
        # Try to parse as xml
        try:
            report_file = open(report_path)
        except Exception as e:
            logger.error("Error reading report content [%s]", e)
        else:
            try:
                for event, elem in ET.iterparse(report_file, ('start',)):
                    main_tag = elem.tag
                    break
                logger.debug("Found XML content on file: %s - Main tag: %s", report_path, main_tag)
            except Exception as e:
                logger.info("Non XML content [%s] - %s", report_path, e)
            finally:
                report_file.close()
                for _plugin_id, _plugin in self.plugin_controller.getAvailablePlugins().items():
                    if _plugin.report_belongs_to(main_tag=main_tag, report_path=report_path, extension=file_extension):
                        plugin_id = _plugin_id
                        break
        return plugin_id

    def _get_plugin_by_name(self, file_name_base):
        plugin_id = None
        plugin_name_regex = r".*_faraday_(?P<plugin_name>.+)\..*$"
        match = re.match(plugin_name_regex, file_name_base)
        if match:
            plugin_id = match.groupdict()['plugin_name'].lower()
            logger.debug("Plugin name match: %s", plugin_id)
            if plugin_id in self.plugin_controller.getAvailablePlugins():
                return plugin_id
            else:
                logger.info("Invalid plugin from file name: %s", plugin_id)
                return None
        else:
            logger.debug("Could not extract plugin_id from filename: %s", file_name_base)
            return plugin_id

# I'm Py3
