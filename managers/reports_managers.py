#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import re
import time
import traceback
from multiprocessing import Process


from utils.logs import getLogger

try:
    import xml.etree.cElementTree as ET

except ImportError:
    print "cElementTree could not be imported. Using ElementTree instead"
    import xml.etree.ElementTree as ET

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class ReportProcessor():
    def __init__(self, plugin_controller, ws_name=None):
        self.plugin_controller = plugin_controller
        self.ws_name = ws_name

    def processReport(self, filename):
        """
        Process one Report
        """
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
        if not self.plugin_controller.processReport(plugin_id, filename, self.ws_name):
            getLogger(self).error(
                "Faraday doesn't have a plugin for this tool..."
                " Processing: ABORT")
            return False
        return True

    def onlinePlugin(self, cmd):

        _, new_cmd = self.plugin_controller.processCommandInput('0', cmd, './')
        self.plugin_controller.onCommandFinished('0', 0, cmd)


class ReportManager(Process):
    def __init__(self, timer, ws_name, plugin_controller):
        Process.__init__(self)
        self.ws_name = ws_name
        self.daemon = True
        self.timer = timer
        self._stop = False
        self._report_path = os.path.join(CONF.getReportPath(), ws_name)
        self._report_ppath = os.path.join(self._report_path, "process")
        self._report_upath = os.path.join(self._report_path, "unprocessed")
        self.processor = ReportProcessor(plugin_controller, ws_name)

        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)

        if not os.path.exists(self._report_ppath):
            os.mkdir(self._report_ppath)

        if not os.path.exists(self._report_upath):
            os.mkdir(self._report_upath)

    def run(self):
        tmp_timer = .0
        tmp_timer_sentinel = 0
        while not self._stop:

            time.sleep(.1)
            tmp_timer += .1
            tmp_timer_sentinel += 1

            if tmp_timer_sentinel == 1800:
                tmp_timer_sentinel = 0
                self.launchSentinel()

            if tmp_timer >= self.timer:
                try:
                    self.syncReports()
                except Exception:
                    getLogger(self).error(
                        "An exception was captured while saving reports\n%s"
                        % traceback.format_exc())
                finally:
                    tmp_timer = 0

    def stop(self):
        self._stop = True

    def launchSentinel(self):
        psettings = CONF.getPluginSettings()

        name, cmd = "Sentinel", "sentinel"
        if name in psettings:
            if psettings[name]['settings']['Enable'] == "1":
                getLogger(self).info("Plugin Started: Sentinel")
                self.processor.onlinePlugin(cmd)
                getLogger(self).info("Plugin Ended: Sentinel")

    def syncReports(self):
        """
        Synchronize report directory using the DataManager and Plugins online
        We first make sure that all shared reports were added to the repo
        """
        filenames = []

        for root, dirs, files in os.walk(self._report_path, False):

            if root == self._report_path:
                for name in files:
                    filenames.append(os.path.join(root, name))

        for filename in filenames:
            name = os.path.basename(filename)

            # If plugin not is detected... move to unprocessed
            if self.processor.processReport(filename) is False:

                os.rename(
                    filename,
                    os.path.join(self._report_upath, name))
            else:
                os.rename(
                    filename,
                    os.path.join(self._report_ppath, name))

        self.onlinePlugins()

    def onlinePlugins(self):
        """
        Process online plugins
        """
        pluginsOn = {"MetasploitOn": "./metasploiton online"}
        pluginsOn.update({"Beef": "./beef online"})
        psettings = CONF.getPluginSettings()

        for name, cmd in pluginsOn.iteritems():
            if name in psettings:
                if psettings[name]['settings']['Enable'] == "1":
                    self.processor.onlinePlugin(cmd)

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
        """

        """
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
            f.seek(0)

            for key in signatures:
                if file_signature.find(key) == 0:

                    result = signatures[key]
                    getLogger(self).debug("Report type detected: %s" % result)
                    break

        except IOError, err:
            self.report_type = None
            getLogger(self).error(
                "Error while opening file.\n%s. %s" % (err, file_path))

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
        else:

            try:
                for event, elem in ET.iterparse(f, ('start', )):
                    result = elem.tag
                    break

            except SyntaxError, err:
                self.report_type = None
                getLogger(self).error("Not an xml file.\n %s" % (err))

        f.seek(0)
        output = f.read()
        if f:
            f.close()

        return result, output

    def rType(self, tag, output):
        """Compares report root tag with known root tags.

        :param root_tag
        :rtype
        """
        if "nmaprun" == tag:
            return "Nmap"
        elif "w3af-run" == tag:
            return "W3af"
        elif "NessusClientData_v2" == tag:
            return "Nessus"
        elif "report" == tag:

            if re.search(
                "https://raw.githubusercontent.com/Arachni/arachni/",
                output) is not None:
                return "Arachni"

            elif re.search("OpenVAS", output) is not None or re.search(
                '<omp><version>',
                output) is not None:
                return "Openvas"

            else:
                return "Zap"

        elif "niktoscan" == tag:
            return "Nikto"
        elif "MetasploitV4" == tag:
            return "Metasploit"
        elif "MetasploitV5" == tag:
            return "Metasploit"
        elif "issues" == tag:
            return "Burp"
        elif "OWASPZAPReport" == tag:
            return "Zap"
        elif "ScanGroup" == tag:
            return "Acunetix"
        elif "session" == tag:
            return "X1"
        elif "landscapePolicy" == tag:
            return "X1"
        elif "entities" == tag:
            return "Core Impact"
        elif "NeXposeSimpleXML" == tag:
            return "Nexpose"
        elif "NexposeReport" == tag:
            return "NexposeFull"
        elif "ASSET_DATA_REPORT" == tag or "SCAN" == tag:
            return "Qualysguard"
        elif "scanJob" == tag:
            return "Retina"
        elif "netsparker" == tag:
            return "Netsparker"
        elif "netsparker-cloud" == tag:
            return "NetsparkerCloud"            
        elif "maltego" == tag:
            return "Maltego"
        elif "lynis" == tag:
            return "Lynis"
        else:
            return None
