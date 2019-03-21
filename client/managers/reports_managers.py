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

from random import random
from threading import Thread, Timer
from faraday.utils.logs import getLogger

from faraday.config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

try:
    import xml.etree.cElementTree as ET
except ImportError:
    print("cElementTree could not be imported. Using ElementTree instead")
    import xml.etree.ElementTree as ET


class OnlinePlugins(Thread):

    def __init__(self, plugin_controller):

        Thread.__init__(self)
        self.setDaemon(True)
        self._stop = False

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
        getLogger(self).debug("Running online plugin...")

    def stop(self):
        self._stop = True

    def run(self):

        while not self._stop:

            for name, config_dict in self.online_plugins.iteritems():
                if name in self.plugins_settings:
                    if self.plugins_settings[name]['settings']['Enable'] == "1":

                        t = Timer(
                            config_dict["time"],
                            self.runPluginThread, args=(config_dict["command"],))

                        getLogger(self).debug(
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
        getLogger(self).debug("Report file is %s" % filename)

        parser = ReportParser(filename)

        if parser.report_type is None:

            getLogger(self).error(
                'Plugin not found: automatic and manual try!')
            return False

        return self.sendReport(parser.report_type, filename)

    def sendReport(self, plugin_id, filename):
        """Sends a report to the appropiate plugin specified by plugin_id"""

        getLogger(self).info(
            'The file is %s, %s' % (filename, plugin_id))

        command_id = self.plugin_controller.processReport(
            plugin_id, filename, ws_name=self.ws_name)

        if not command_id:

            getLogger(self).error(
                "Faraday doesn't have a plugin for this tool... Processing: ABORT")
            return False

        return command_id


class ReportManager(Thread):

    def __init__(self, timer, ws_name, plugin_controller, polling=True):

        Thread.__init__(self)
        self.setDaemon(True)

        self.polling = polling
        self.ws_name = ws_name
        self.timer = timer
        self._stop = False

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

        while not self._stop:

            time.sleep(.1)
            tmp_timer += .1

            if tmp_timer >= self.timer:

                try:
                    self.syncReports()
                    if not self.polling:
                        break

                except Exception:

                    getLogger(self).error(
                        "An exception was captured while saving reports\n%s"
                        % traceback.format_exc())

                finally:
                    tmp_timer = 0

    def stop(self):
        self._stop = True
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

                        getLogger(self).info(
                            'Plugin not detected. Moving {0} to unprocessed'.format(filename))

                        os.rename(
                            filename,
                            os.path.join(self._report_upath, name))
                    else:

                        getLogger(self).info(
                            'Detected valid report {0}'.format(filename))

                        os.rename(
                            filename,
                            os.path.join(self._report_ppath, name))

    def sendReportToPluginById(self, plugin_id, filename):
        """Sends a report to be processed by the specified plugin_id"""
        self.processor.sendReport(plugin_id, filename)


class ReportParser(object):
    """
    Class that handles reports files.
    :param filepath: report file.
    :class:`.LoadReport`
    """

    def __init__(self, report_path):
        self.report_type = None
        root_tag, output = self.getRootTag(report_path)

        if root_tag:
            self.report_type = self.rType(root_tag, output)

        if self.report_type is None:

            getLogger(self).debug(
                'Automatical detection FAILED... Trying manual...')

            self.report_type = self.getUserPluginName(report_path)

    def getUserPluginName(self, pathFile):

        if pathFile == None:
            return None

        rname = pathFile[pathFile.rfind('/') + 1:]
        ext = rname.rfind('.')
        if ext < 0:
            ext = len(rname) + 1
        rname = rname[0:ext]
        faraday_index = rname.rfind('_faraday_')
        if faraday_index > -1:
            plugin = rname[faraday_index + 9:]
            return plugin

        return None

    def open_file(self, file_path):
        """
        This method uses file signatures to recognize file types

        :param file_path: report file.

        If you need add support to a new report type
        add the file signature here
        and add the code in self.getRootTag() for get the root tag.
        """
        f = result = None

        signatures = {
            "\x50\x4B": "zip",
            "\x3C\x3F\x78\x6D\x6C": "xml",
            "# Lynis Re": "dat",
        }

        try:

            if file_path == None:
                return None, None

            f = open(file_path, 'rb')
            file_signature = f.read(10)

            for key in signatures:
                if file_signature.find(key) == 0:

                    result = signatures[key]
                    break

            if not result:
                # try json loads to detect a json file.
                try:
                    f.seek(0)
                    json.loads(f.read())
                    result = 'json'
                except ValueError:
                    pass

        except IOError as err:
            self.report_type = None
            getLogger(self).error(
                "Error while opening file.\n%s. %s" % (err, file_path))

        getLogger(self).debug("Report type detected: %s" % result)
        f.seek(0)
        return f, result

    def getRootTag(self, file_path):

        report_type = result = f = None

        f, report_type = self.open_file(file_path)

        # Check error in open_file()
        if f is None and report_type is None:
            self.report_type = None
            return None, None

        # Find root tag based in report_type
        if report_type == "zip":
            result = "maltego"
        elif report_type == "dat":
            result = 'lynis'
        elif report_type == 'json':
            # this will work since recon-ng is the first plugin to use json.
            # we need to add json detection here!
            result = 'reconng'
        else:

            try:
                for event, elem in ET.iterparse(f, ('start', )):
                    result = elem.tag
                    break

            except SyntaxError as err:
                self.report_type = None
                getLogger(self).error("Not an xml file.\n %s" % (err))

        f.seek(0)
        output = f.read()
        if f:
            f.close()

        return result, output

    def rType(self, tag, output):
        """ Compares report root tag with known root tags """
        if tag == "nmaprun":
            return "Nmap"
        elif tag == "w3af-run":
            return "W3af"
        elif tag == "NessusClientData_v2":
            return "Nessus"
        elif tag == "report":

            if re.search(
                    "https://raw.githubusercontent.com/Arachni/arachni/", output) is not None:
                return "Arachni"

            elif re.search("OpenVAS", output) is not None or re.search('<omp><version>', output) is not None:
                return "Openvas"

            else:
                return "Zap"

        elif tag == "xml-report":
            if re.search("Appscan", output) is not None:
                return "Appscan"
        elif tag == "niktoscan":
            return "Nikto"
        elif tag == "MetasploitV4":
            return "Metasploit"
        elif tag == "MetasploitV5":
            return "Metasploit"
        elif tag == "issues":
            return "Burp"
        elif tag == "OWASPZAPReport":
            return "Zap"
        elif tag == "ScanGroup":
            return "Acunetix"
        elif tag == "session":
            return "X1"
        elif tag == "landscapePolicy":
            return "X1"
        elif tag == "entities":
            return "Core Impact"
        elif tag == "NexposeReport":
            return "NexposeFull"
        elif tag in ("ASSET_DATA_REPORT", "SCAN"):
            return "Qualysguard"
        elif tag == "scanJob":
            return "Retina"
        elif tag == "netsparker":
            return "Netsparker"
        elif tag == "netsparker-cloud":
            return "NetsparkerCloud"
        elif tag == "maltego":
            return "Maltego"
        elif tag == "lynis":
            return "Lynis"
        elif tag == "reconng":
            return "Reconng"
        elif tag == "document":
            if re.search("SSLyzeVersion", output) is not None:
                return "Sslyze"
        else:
            return None
