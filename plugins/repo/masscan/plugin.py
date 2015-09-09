'''
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from plugins.repo.nmap.plugin import NmapPlugin
import os
import re
import random

current_path = os.path.abspath(os.getcwd())


class CmdMasscanPlugin(NmapPlugin):
    """
    Example plugin to parse amap output.
    """
    def __init__(self):
        NmapPlugin.__init__(self)
        self.id              = "Masscan"
        self.name            = "Masscan Output Plugin"
        self.plugin_version         = "0.0.1"
        self.version   = "1.0.3"
        self.options         = None
        self._command_regex  = re.compile(r'^(masscan|sudo masscan|\.\/masscan|sudo \.\/masscan).*?')  
        self._output_file_path = os.path.join(self.data_path,
                                             "masscan_output-%s.xml" % self._rid)

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -oX parameter to get xml output to the command string that the
        user has set.
        """
        self._output_file_path = os.path.join(self.data_path,"masscan_output-%s.xml" % random.uniform(1,10))        

        arg_match = self.xml_arg_re.match(command_string)


        if arg_match is None:
            return re.sub(r"(^.*?masscan)",
                          r"\1 -oX %s" % self._output_file_path,
                          command_string)
        else:
            return re.sub(arg_match.group(1),
                          r"-oX %s" % self._output_file_path,
                          command_string)


def createPlugin():
    return CmdMasscanPlugin()
