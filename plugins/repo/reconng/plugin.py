#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''
import re

from plugins.core import PluginBase

__author__ = 'Leonardo Lazzaro'
__copyright__ = 'Copyright (c) 2017, Infobyte LLC'
__credits__ = ['Leonardo Lazzaro']
__license__ = ''
__version__ = '0.1.0'
__maintainer__ = 'Leonardo Lazzaro'
__email__ = 'leonardol@infobytesec.com'
__status__ = 'Development'


class ReconngPlugin(PluginBase):
    """
    Example plugin to parse qualysguard output.
    """

    def __init__(self):

        PluginBase.__init__(self)
        self.id = 'Reconng'
        self.name = 'Reconng XML Output Plugin'
        self.plugin_version = '0.0.2'
        self.version = ''
        self.framework_version = ''
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(
            r'records added to')
        self.importing_report = False

    def parseOutputString(self, output):
        pass

    def parseCommandString(self, username, current_path, command_string):
        self.importing_report = False

def createPlugin():
    return ReconngPlugin()