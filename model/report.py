#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
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

"""

"""
                                                                                
class ReportManager(threading.Thread):
    def __init__(self, timer, plugin_controller, path=None):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.timer = timer
        self._stop = False
        self.path = path
        self.plugin_controller = plugin_controller

    def run(self):
        tmp_timer = 0
        while not self._stop:
                                   
            time.sleep(1)
            tmp_timer += 1
            if tmp_timer == self.timer:
                try:
                    self.syncReports()
                except Exception:
                    model.api.devlog("An exception was captured while saving reports\n%s" % traceback.format_exc())
                finally:
                    tmp_timer = 0

    def stop(self):
        self._stop = True
        
      
    def syncReports(self):
        """
        Synchronize report directory using the DataManager and Plugins online
        We first make sure that all shared reports were added to the repo
        """
        
        
        self._xml_output_path = self.path
        if self._xml_output_path is None:
            return
            
        if not os.path.exists(self._xml_output_path):
            return False
        
        for root, dirs, files in os.walk(self._xml_output_path,False):
                            
            if root == self._xml_output_path:
                for name in files:
                    filename = os.path.join(root, name)
                    
                                                                          
                    model.api.devlog( "Report file is %s" % filename)
                    
                                     
                    parser = ReportXmlParser(filename)
                    if (parser.report_type is not None):
                        #TODO: get host and port from config
                        client = PluginControllerAPIClient("127.0.0.1", 9977)

                        #self._xml_output_path = filename
                        model.api.devlog("The file is %s, %s" % (filename,parser.report_type))

                        command_string = "./%s report" % parser.report_type.lower()
                        model.api.devlog("Executing %s" % (command_string))
                        
                        # current_path =""
  
                        # new_cmd = self.plugin_controller.processCommandInput("", "",
                        #                                                          current_path,
                        #                                                          command_string,
                        #                                                          False)
                        new_cmd, output_file = client.send_cmd(command_string)
                        
                        #self.plugin_controller.storeCommandOutput(self._xml_output_path)
                        client.send_output(command_string, filename)
                        
                        #self.plugin_controller.onCommandFinished()
                        
                        
                                     
                    os.rename(filename, os.path.join(root,"process", name))
        
                               
        self.onlinePlugins()

                    
    def onlinePlugins(self):
        """
        Process online plugins
        """
        _pluginsOn={"MetasploitOn" : "./metasploiton online",}
        _pluginsOn={"Beef" : "./beef online",}
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
                            

                                                                                
class ReportXmlParser(object):
    
    """Plugin that handles XML report files.
    
    :param xml_filepath: Xml file.
    
    :class:`.LoadReportXML`
    """

    def __init__(self, xml_report_path):
        self.report_type = ""
        root_tag,output = self.getRootTag(xml_report_path)

        if root_tag:
            self.report_type = self.rType(root_tag,output)
        model.api.devlog(self.report_type)
        
    def getRootTag(self, xml_file_path):
        result = f = None
        try:
            f = open(xml_file_path, 'rb')
            try:
                for event, elem in ET.iterparse(f, ('start', )):
                    result = elem.tag
                    break
            except SyntaxError, err:
                self.report_type = None
                model.api.devlog("Not an xml file.\n %s" % (err))

        except IOError, err:
            self.report_type = None
            model.api.devlog("Error while opening file.\n%s. %s" % (err, xml_file_path))
        finally:
            f.seek(0)
            output=f.read()
            if f: f.close()
            
        return result,output
                    
    def rType(self, tag, output):
        """Compares report root tag with known root tags.
        
        :param root_tag
        :rtype
        """
        if "arachni_report" == tag:
            return "arachni"
        elif "nmaprun" == tag:
            return "nmap"
        elif "w3afrun" == tag:
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
        elif "issues" == tag:
            return "burp"
        elif "OWASPZAPReport" == tag:
            return "zap"
        elif "ScanGroup" == tag:
            return "acunetix"
        elif "session" == tag:
            return "x1"
        elif "entities" == tag:
            return "impact"
        elif "NeXposeSimpleXML" == tag:
            return "nexpose"
        elif "SCAN" == tag:
            return "qualysguard"
        elif "scanJob" == tag:
            return "retina"
        elif "netsparker" == tag:
            return "netsparker"
        else:
            return None

