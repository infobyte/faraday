#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import model.api
import threading
import time
import traceback
import re
import requests
try:
    import xml.etree.cElementTree as ET

except ImportError:
    print "cElementTree could not be imported. Using ElementTree instead"
    import xml.etree.ElementTree as ET
from apis.rest.api import PluginControllerAPIClient

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

class NoReportsWatchException(Exception): pass

class ReportManager(threading.Thread):
    def __init__(self, timer, plugin_controller, path=None):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.timer = timer
        self._stop = False
        self.path = path
        self.plugin_controller = plugin_controller
        self._report_path = None
        self._report_ppath = None

    def run(self):
        tmp_timer = 0
        while not self._stop:

            time.sleep(1)
            tmp_timer += 1
            if tmp_timer == self.timer:
                try:
                    self.syncReports()
                except Exception:
                    model.api.log("An exception was captured while saving reports\n%s" % traceback.format_exc())
                finally:
                    tmp_timer = 0

    def stop(self):
        self._stop = True

    def watch(self, name):
        self._report_path = os.path.join(CONF.getReportPath(), name)
        self._report_ppath = os.path.join(self._report_path, "process")

        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)

        if not os.path.exists(self._report_ppath):
            os.mkdir(self._report_ppath)

    def startWatch(self):
        if not self._report_path:
            raise NoReportsWatchException()
        self.start()

    def syncReports(self):
        """
        Synchronize report directory using the DataManager and Plugins online
        We first make sure that all shared reports were added to the repo
        """

        for root, dirs, files in os.walk(self._report_path, False):

            if root == self._report_path:
                for name in files:
                    filename = os.path.join(root, name)
                    model.api.log( "Report file is %s" % filename)

                    parser = ReportParser(filename)
                    if (parser.report_type is not None):

                        host = CONF.getApiConInfoHost()
                        port_rest = int(CONF.getApiRestfulConInfoPort())

                        client = PluginControllerAPIClient(host, port_rest)

                        model.api.log("The file is %s, %s" % (filename,parser.report_type))

                        command_string = "./%s %s" % (parser.report_type.lower(), filename)
                        model.api.log("Executing %s" % (command_string))

                        new_cmd, output_file = client.send_cmd(command_string)
                        client.send_output(command_string, filename)
                    os.rename(filename, os.path.join(self._report_ppath, name))

        self.onlinePlugins()


    def onlinePlugins(self):
        """
        Process online plugins
        """
        _pluginsOn={"MetasploitOn" : "./metasploiton online",}
        _pluginsOn.update({"Beef" : "./beef online",})
        _psettings=CONF.getPluginSettings()

        for k,v in _pluginsOn.iteritems():
            if k in _psettings:
                if _psettings[k]['settings']['Enable'] == "1":
                    new_cmd = self.plugin_controller.processCommandInput("", "",
                                                                             "",
                                                                             v,
                                                                             False)

                    self.plugin_controller.storeCommandOutput("")

                    self.plugin_controller.onCommandFinished()



class ReportParser(object):

    """
    Class that handles reports files.

    :param filepath: report file.

    :class:`.LoadReport`
    """

    def __init__(self, report_path):
        self.report_type = ""
        root_tag, output = self.getRootTag(report_path)

        if root_tag:
            self.report_type = self.rType(root_tag, output)

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
         "\x50\x4B" : "zip" ,
         "\x3C\x3F\x78\x6D\x6C" : "xml"
        }

        try:
            f = open(file_path, 'rb')
            file_signature = f.read(10)
            f.seek(0)

            for key in signatures:
                if file_signature.find(key) == 0:

                    result = signatures[key]
                    model.api.log("Report type detected: %s" %result)
                    break

        except IOError, err:
            self.report_type = None
            model.api.log("Error while opening file.\n%s. %s" % (err, file_path))

        return f, result

    def getRootTag(self, file_path):

        report_type = result = f = None

        f, report_type = self.open_file(file_path)

        #Check error in open_file()
        if f == None and report_type == None:
            self.report_type = None
            return None, None

        #Find root tag based in report_type
        if report_type == "zip":
            result = "maltego"

        elif report_type == "xml":

            try:
                for event, elem in ET.iterparse(f, ('start', )):
                    result = elem.tag
                    break

            except SyntaxError, err:
                self.report_type = None
                model.api.log("Not an xml file.\n %s" % (err))

        f.seek(0)
        output = f.read()
        if f: f.close()

        return result, output

    def rType(self, tag, output):
        """Compares report root tag with known root tags.

        :param root_tag
        :rtype
        """
        if "arachni_report" == tag:
            return "arachni"
        elif "nmaprun" == tag:
            return "nmap"
        elif "w3af-run" == tag:
            return "w3af"
        elif "NessusClientData_v2" == tag:
            return "nessus"
        elif "report" == tag:
            if re.search("alertitem",output) is None:
                return "openvas"
            else:
                return "zap"
        elif "niktoscan" == tag:
            return "nikto"
        elif "MetasploitV4" == tag:
            return "metasploit"
        elif "MetasploitV5" == tag:
            return "metasploit"
        elif "issues" == tag:
            return "burp"
        elif "OWASPZAPReport" == tag:
            return "zap"
        elif "ScanGroup" == tag:
            return "acunetix"
        elif "session" == tag:
            return "x1"
        elif "landscapePolicy" == tag:
            return "x1"
        elif "entities" == tag:
            return "impact"
        elif "NeXposeSimpleXML" == tag:
            return "nexpose"
        elif "NexposeReport" == tag:
            return "nexpose-full"
        elif "SCAN" == tag:
            return "qualysguard"
        elif "scanJob" == tag:
            return "retina"
        elif "netsparker" == tag:
            return "netsparker"
        elif "maltego" == tag:
            return "maltego_faraday"
        else:
            return None
