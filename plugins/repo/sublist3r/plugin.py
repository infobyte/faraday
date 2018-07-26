#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import re
import os
import shlex
import socket
import argparse
import tempfile
from plugins.plugin import PluginTerminalOutput


__author__ = "Matías Lang"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Matías Lang"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Matías Lang"
__email__ = "matiasl@infobytesec.com"
__status__ = "Development"


class Sublist3rPlugin(PluginTerminalOutput):
    def __init__(self):
        super(Sublist3rPlugin, self).__init__()
        self.id = "sublist3r"
        self.name = "sublist3r"
        self.plugin_version = "0.0.1"
        self.version = "0.0.1"
        self._command_regex = re.compile(
            r'^(sudo )?(python[0-9\.]? )?sublist3r(\.py)?')
        self.ignore_parsing = False
        self.report_file = None

    def parseOutputString(self, output, debug=False):
        if self.ignore_parsing:
            return
        if self.report_file:
            # We ran the plugin via command line
            try:
                fp = open(self.report_file)
            except IOError:
                self.log('Error opening report file {}'.format(
                    self.report_file
                ), 'ERROR')
            else:
                self.parse_report(fp.read())
                if self.remove_report:
                    os.unlink(self.report_file)
        else:
            # We are importing a report
            self.parse_report(output)

    def resolve(self, domain):
        return socket.gethostbyname(domain)

    def parse_report(self, contents):
        for line in contents.splitlines():
            hostname = line.strip()
            if not hostname:
                continue
            try:
                ip = self.resolve(hostname)
            except socket.gaierror:
                self.log('Error resolving hostname {}. Skipping.'.format(
                    hostname
                ), 'ERROR')
                continue
            h_id = self.createAndAddHost(ip)

            self.createAndAddInterface(
                h_id,
                name=ip,
                ipv4_address=ip,
                hostname_resolution=[hostname])

    def processCommandString(self, username, current_path, command_string):
        parser = argparse.ArgumentParser(conflict_handler='resolve')
        parser.add_argument('-h', '--help', action='store_true')
        parser.add_argument('-o', '--output')
        args, unknown = parser.parse_known_args(shlex.split(command_string))

        if args.help:
            self.devlog('help detected, ignoring parsing')
            return command_string
        if args.output:
            # The user already defined a path to the report
            self.report_file = args.output
            self.remove_report = False
            return command_string
        else:
            # Use temporal file to save the report data
            self.report_file = tempfile.mktemp(
                prefix="sublist3r_report_", suffix=".txt")
            self.devlog('Setting report file to {}'.format(
                self.report_file))
            self.remove_report = True
            return '{} --output {}'.format(command_string,
                                           self.report_file)


def createPlugin():
    return Sublist3rPlugin()
