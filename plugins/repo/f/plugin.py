#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import with_statement
from plugins import core
from model import api
import re
import os
import shlex
import argparse
import sys
import random
from StringIO import StringIO
import traceback
#current_path = os.path.abspath(os.getcwd())


class FPlugin(core.PluginBase):
    """
    Example plugin to parse f output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "faraday"
        self.name = "Faraday Output Plugin"
        self.plugin_version = "0.0.2"
        self.version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(
            r'^(sudo fplugin|sudo \./fplugin|\./fplugin).*?')
        self._hosts = []
        self.args = None
        self._completition = {
            "": "f [i &lt;Python Code&gt;]",
            "-e": "execute model directly",
            "-o": "output command",
        }

    def parseOutputString(self, output, debug=False):
        pass

    file_arg_re = re.compile(r"^.*(-o\s*[^\s]+).*$")

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -m parameter to get machine readable output.
        """
        arg_match = self.file_arg_re.match(command_string)
        self._file_output_path = os.path.join(
            self.data_path, "f_output-%s.txt" % random.uniform(1, 10))

        parser = argparse.ArgumentParser()

        parser.add_argument('-e')
        parser.add_argument('-f')
        parser.add_argument('-o')

        # NO support -h --help style parameters.
        # Need "" in all parameter. Example script.py -p "parameter1
        # parameter2"
        parser.add_argument('-p')

        if arg_match is None:
            final = re.sub(r"(^.*?fplugin)",
                           r"\1 -o %s" % self._file_output_path,
                           command_string)
        else:
            final = re.sub(arg_match.group(1),
                           r"-o %s" % self._file_output_path,
                           command_string)

        cmd = shlex.split(re.sub(r'\-h|\-\-help', r'', final))
        try:
            self.args, unknown = parser.parse_known_args(cmd)
        except SystemExit:
            pass

        codeEx = ""
        if self.args.e:
            codeEx = self.args.e
        elif self.args.f:
            with open(current_path + "/" + self.args.f) as f:
                codeEx = f.read()
            f.close()

        if codeEx:
            buffer = StringIO()
            sys.stdout = buffer

            try:
                locales = locals()
                locales.update({'script_parameters': self.args.p})
                exec(codeEx, globals(), locales)

            except Exception:
                api.devlog("[Error] - Faraday plugin")
                api.devlog(traceback.format_exc())

            sys.stdout = sys.__stdout__

            try:
                f = open(self._file_output_path, "w")
                f.write(buffer.getvalue())
                f.close()
            except:
                api.devlog("[Faraday] Can't save faraday plugin output file")
                return

        return final

    def setHost(self):
        pass


def createPlugin():
    return FPlugin()
