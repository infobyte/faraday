#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Author: @EzequielTBH

from plugins import core
import json
import re

__author__     = "@EzequielTBH"
__copyright__  = "Copyright 2015, @EzequielTBH"
__credits__    = "@EzequielTBH"
__license__    = "GPL v3"
__version__    = "1.0.0"

class pasteAnalyzerPlugin(core.PluginBase):

    def __init__(self):
             core.PluginBase.__init__(self)
             self.id              = "pasteAnalyzer"
             self.name            = "pasteAnalyzer JSON Output Plugin"
             self.plugin_version  = "1.0.0"
             self.command_string  = ""
             self.current_path    = ""
             self._command_regex  = re.compile(
                 r'^(pasteAnalyzer|python pasteAnalyzer.py|\./pasteAnalyzer.py|sudo python pasteAnalyzer.py|sudo \./pasteAnalyzer.py).*?')


    def parseOutputString(self, output, debug = False):

        print("[*]Parsing Output...")

        #Generating file name with full path.
        indexStart = self.command_string.find("-j") + 3

        fileJson = self.command_string [ indexStart :
             self.command_string.find(" ", indexStart) ]

        fileJson = self.current_path + "/" + fileJson

        try:
            with open(fileJson,"r") as fileJ:
                results = json.loads( fileJ.read() )

        except Exception as e:
            print("\n[!]Exception opening file\n" + str(e) )
            return

        if results == []:
            return

        print("[*]Results loaded...")

        #Configuration initial.
        hostId = self.createAndAddHost("pasteAnalyzer")
        interfaceId = self.createAndAddInterface(hostId, "Results")
        serviceId = self.createAndAddServiceToInterface(
             hostId,
             interfaceId,
             "Web",
             "TcpHTTP",
             ['80']
             )
        print("[*]Initial Configuration ready....")

        #Loading results.
        for i in range(0, len(results), 2 ):

            data = results[i + 1]
            description = ""

            for element in data:

                #Is Category
                if type(element) == str or type(element) == unicode:
                    description +=  element +": "

                #Is a list with results!
                else:
                    for element2 in element:
                        description += "\n" +  element2

            self.createAndAddVulnWebToService(
                hostId,
                serviceId,
                results[i],
                description
                )

        print("[*]Parse finished, API faraday called...")

    def processCommandString(self, username, current_path, command_string):

        print("[*]pasteAnalyzer Plugin running...")

        if command_string.find("-j") < 0:
            command_string += " -j JSON_OUTPUT "

        self.command_string = command_string
        self.current_path = current_path

        return command_string

def createPlugin():
    return pasteAnalyzerPlugin()



