import logging
import traceback
from datetime import datetime
import json
import re
from threading import Thread
from queue import Queue, Empty
import time
import os
import sys
import requests
import pkgutil
from importlib import import_module
from importlib.machinery import SourceFileLoader
import faraday.server.config
from faraday.config.configuration import getInstanceConfiguration
from faraday.server.api.modules import bulk_create as bc
import faraday_plugins.plugins.repo

CONF = getInstanceConfiguration()

logger = logging.getLogger(__name__)

try:
    import xml.etree.cElementTree as ET
except ImportError:
    logger.warning("cElementTree could not be imported. Using ElementTree instead")
    import xml.etree.ElementTree as ET

REPORTS_QUEUE = Queue()


class ReportAnalyzer:

    def __init__(self, plugin_manager):
        self.plugin_manager = plugin_manager

    def get_plugin(self, report_path):
        plugin = None
        if not os.path.isfile(report_path):
            logger.error("Report [%s] don't exists", report_path)
            return plugin
        else:
            file_name = os.path.basename(report_path)
            plugin = self._get_plugin_by_name(file_name)
            if not plugin:   # Was unable to detect plugin from report file name
                logger.debug("Plugin by name not found")
                plugin = self._get_plugin_by_file_type(report_path)
                if not plugin:
                    logger.debug("Plugin by file not found")
        if not plugin:
            logger.info("Plugin for file (%s) not found", report_path)
        return plugin

    def _get_plugin_by_name(self, file_name_base):
        plugin_id = None
        plugin_name_regex = r".*_faraday_(?P<plugin_name>.+)\..*$"
        match = re.match(plugin_name_regex, file_name_base)
        if match:
            plugin_id = match.groupdict()['plugin_name'].lower()
            logger.debug("Plugin name match: %s", plugin_id)
            plugin = self.plugin_manager.get_plugin(plugin_id)
            if plugin:
                logger.debug("Plugin by name Found: %s", plugin.id)
                return plugin
            else:
                logger.info("Invalid plugin from file name: %s", plugin_id)
                return None
        else:
            logger.debug("Could not extract plugin_id from filename: %s", file_name_base)
            return plugin_id

    def _get_plugin_by_file_type(self, report_path):
        plugin = None
        file_name = os.path.basename(report_path)
        file_name_base, file_extension = os.path.splitext(file_name)
        file_extension = file_extension.lower()
        main_tag = None
        logger.debug("Analyze report File")
        # Try to parse as xml
        try:
            report_file = open(report_path, "rb")
        except Exception as e:
            logger.error("Error reading report content [%s]", e)
        else:
            try:
                for event, elem in ET.iterparse(report_file, ('start',)):
                    main_tag = elem.tag
                    break
                logger.info("Found XML content on file: %s - Main tag: %s", report_path, main_tag)
            except Exception as e:
                logger.info("Non XML content [%s] - %s", report_path, e)
            finally:
                report_file.close()
                for _plugin_id, _plugin in self.plugin_manager.get_plugins():
                    logger.debug("Try: %s", _plugin_id)
                    try:
                        if _plugin.report_belongs_to(main_tag=main_tag, report_path=report_path, extension=file_extension):
                            plugin = _plugin
                            logger.info("Plugin by File Found: %s", plugin.id)
                            break
                    except Exception as e:
                        logger.error("Error in plugin analysis: (%s) %s", _plugin_id, e)
        return plugin


class PluginsManager:

    def __init__(self):
        self.plugins = {}
        self.plugin_modules = {}
        self._load_plugins()

    def _load_plugins(self):
        logger.info("Loading Native Plugins...")
        for _, name, _ in filter(lambda x: x[2], pkgutil.iter_modules(faraday_plugins.plugins.repo.__path__)):
            try:
                plugin_module = import_module(f"faraday_plugins.plugins.repo.{name}.plugin")
                if hasattr(plugin_module, "createPlugin"):
                    plugin_instance = plugin_module.createPlugin()
                    plugin_id = plugin_instance.id.lower()
                    if plugin_id not in self.plugin_modules:
                        self.plugin_modules[plugin_id] = plugin_module
                        logger.debug("Load Plugin: %s", name)
                    else:
                        logger.debug("Plugin already loaded: %s", plugin_id)
                else:
                    logger.error("Invalid Plugin: %s", name)
            except Exception as e:
                logger.error("Cant load plugin module: %s [%s]", name, e)
        if os.path.isdir(faraday.server.config.faraday_server.custom_plugins_folder):
            logger.info("Loading Custom Plugins...")
            dir_name_regexp = re.compile(r"^[\d\w\-\_]+$")
            for name in os.listdir(faraday.server.config.faraday_server.custom_plugins_folder):
                if dir_name_regexp.match(name) and name != "__pycache__":
                    try:
                        module_path = os.path.join(faraday.server.config.faraday_server.custom_plugins_folder, name)
                        sys.path.append(module_path)
                        module_filename = os.path.join(module_path, "plugin.py")
                        file_ext = os.path.splitext(module_filename)[1]
                        if file_ext.lower() == '.py':
                            loader = SourceFileLoader(name, module_filename)
                            self.plugin_modules[name] = loader.load_module()
                        logger.debug('Loading plugin {0}'.format(name))
                    except Exception as e:
                        logger.debug("An error ocurred while loading plugin %s.\n%s", module_filename, traceback.format_exc())
                        logger.warning(e)
        logger.info("%s plugins loaded", len(self.plugin_modules))

    def get_plugin(self, plugin_id):
        plugin = None
        if plugin_id in self.plugin_modules:
            logger.error("Unknown Plugin: %s", plugin_id)
            plugin = self.plugin_modules[plugin_id].createPlugin()
        return plugin

    def get_plugins(self):
        for plugin_id, plugin_module in self.plugin_modules.items():
            logger.debug("Instance Plugin: %s", plugin_id)
            yield plugin_id, plugin_module.createPlugin()

class ReportsManager(Thread):

    def __init__(self, upload_reports_queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.upload_reports_queue = upload_reports_queue
        self.plugins_manager = PluginsManager()
        self._must_stop = False

    def stop(self):
        logger.debug("Stop Reports Manager")
        self._must_stop = True

    def send_report_request(self, workspace, report_json, session_cookie):
        cookies = {'session': session_cookie}
        headers = {'Accept': 'application/json'}
        url = f"http://localhost:5985/_api/v2/ws/{workspace}/bulk_create/"
        r = requests.post(url, headers=headers, cookies=cookies, json=report_json)
        if r.status_code != requests.codes.CREATED:
            logger.warning("Bulk Create Response: %s", r.status_code)
            logger.warning("Bulk Create Response Text: %s", r.text)
            logger.info("Data sended: %s", report_json)
        else:
            logger.info("Bulk Create Response: %s", r.status_code)

    def process_report(self, workspace, file_path, cookies):
        session = cookies['session']
        report_analyzer = ReportAnalyzer(self.plugins_manager)
        plugin = report_analyzer.get_plugin(file_path)
        if plugin:
            with open(file_path, encoding="utf-8") as f:
                try:
                    plugin.parseOutputString(f.read())
                    vulns_data = plugin.get_data()
                    vulns_data["command"]["command"] = os.path.basename(file_path)
                    vulns_data["command"]["user"] = "faraday"
                    #vulns_data["command"]["start_date"] = datetime(2019, 9, 17, 13, 18, 48, 933097)
                    #vulns_data["command"]["end_date"] = datetime(2019, 9, 17, 13, 18, 49, 933097)
                    #vulns_data["command"]["creator"] = 1
                    #duration = vulns_data["command"].pop("duration")
                    del plugin
                    #logger.info("Vulns Data: %s", json.loads(vulns_data))
                except Exception as e:
                    logger.error("Parse Error: %s", e)
                    logger.exception(e)
                else:
                    try:
                        #bc.bulk_create(workspace, vulns_data, True)
                        self.send_report_request(workspace, vulns_data, session)
                    except Exception as e:
                        logger.error("Save Error: %s", e)

    def run(self):
        logger.debug("Start Reports Manager")
        while not self._must_stop:
            try:
                workspace, file_path, cookies = self.upload_reports_queue.get(False, timeout=0.1)
                logger.info("Processing raw report %s", file_path)
                if os.path.isfile(file_path):
                    try:
                        self.process_report(workspace, file_path, cookies)
                    finally:
                        os.remove(file_path)
                else:
                    logger.warning("Report file (%s) don't exists", file_path)
            except Empty:
                time.sleep(0.1)
            except KeyboardInterrupt as ex:
                logger.info("Keyboard interrupt, stopping report processing thread")
                self.stop()
            except Exception as ex:
                logger.exception(ex)
                continue