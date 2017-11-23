#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import re
import os
import json
import shlex
import socket
import argparse
import tempfile
import urlparse
from plugins.plugin import PluginTerminalOutput
from plugins.plugin_utils import get_vulnweb_url_fields


__author__ = "Matías Lang"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Matías Lang"]
__license__ = ""
__version__ = "0.0.1"
__maintainer__ = "Matías Lang"
__email__ = "matiasl@infobytesec.com"
__status__ = "Development"


status_codes = {
    200: "OK", 201:  "Created", 202:  "Accepted",
    203: "Non-Authoritative Information", 204:  "No Content",
    205: "Reset Content", 206:  "Partial Content", 207:  "Multi-Status",
    208: "Already Reported", 226:  "IM Used", 300:  "Multiple Choices",
    301: "Moved Permanently", 302:  "Found", 303:  "See Other",
    304: "Not Modified", 305:  "Use Proxy", 306:  "Switch Proxy",
    307: "Temporary Redirect", 308:  "Permanent Redirect",
    400: "Bad Request", 401:  "Unauthorized", 402:  "Payment Required",
    403: "Forbidden", 404:  "Not Found", 405:  "Method Not Allowed",
    406: "Not Acceptable", 407:  "Proxy Authentication Required",
    408: "Request Timeout", 409:  "Conflict", 410:  "Gone",
    411: "Length Required", 412:  "Precondition Failed",
    413: "Payload Too Large", 414:  "URI Too Long",
    415: "Unsupported Media Type", 416:  "Range Not Satisfiable",
    417: "Expectation Failed", 418:  "I'm a teapot",
    421: "Misdirected Request", 422:  "Unprocessable Entity", 423:  "Locked",
    424: "Failed Dependency", 426:  "Upgrade Required",
    428: "Precondition Required", 429:  "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons", 500:  "Internal Server Error",
    501: "Not Implemented", 502:  "Bad Gateway", 503:  "Service Unavailable",
    504: "Gateway Timeout", 505:  "HTTP Version Not Supported",
    506: "Variant Also Negotiates", 507:  "Insufficient Storage",
    508: "Loop Detected", 510:  "Not Extended",
    511: "Network Authentication Required",
}


class DirsearchPlugin(PluginTerminalOutput):
    def __init__(self):
        super(DirsearchPlugin, self).__init__()
        self.id = "dirsearch"
        self.name = "dirsearch"
        self.plugin_version = "0.0.1"
        self.version = "0.0.1"
        self._command_regex = re.compile(
            r'^(sudo )?(python[0-9\.]? )?dirsearch(\.py)?')
        self.ignore_parsing = False
        self.json_report_file = None
        self.addSetting("Ignore 403", str, "1")

    def parseOutputString(self, output, debug=False):
        if self.ignore_parsing:
            return
        if self.json_report_file:
            # We ran the plugin via command line
            try:
                fp = open(self.json_report_file)
            except IOError:
                self.log('Error opening JSON in the file {}'.format(
                    self.json_report_file
                ), 'ERROR')
            else:
                self.parse_json(fp.read())
                if self.remove_report:
                    os.unlink(self.json_report_file)
        else:
            # We are importing a report
            self.parse_json(output)

    def resolve(self, domain):
        return socket.gethostbyname(domain)

    @property
    def should_ignore_403(self):
        val = self.getSetting('Ignore 403')
        if not val or not int(val):
            return False
        return True

    def parse_json(self, contents):
        try:
            data = json.loads(contents)
        except ValueError:
            self.log('Error parsing report. Make sure the file has valid '
                     'JSON', 'ERROR')
            return
        for (base_url, items) in data.items():
            base_split = urlparse.urlsplit(base_url)
            ip = self.resolve(base_split.hostname)
            h_id = self.createAndAddHost(ip)

            i_id = self.createAndAddInterface(
                h_id,
                name=ip,
                ipv4_address=ip,
                hostname_resolution=[base_split.hostname])

            s_id = self.createAndAddServiceToInterface(
                h_id,
                i_id,
                base_split.scheme,
                'tcp',
                [base_split.port],
                status="open")

            for item in items:
                self.parse_found_url(base_url, h_id, s_id, item)

    def parse_found_url(self, base_url, h_id, s_id, item):
        if self.should_ignore_403 and item['status'] == 403:
            return
        url = urlparse.urlsplit(urlparse.urljoin(base_url, item['path']))
        response = "HTTP/1.1 {} {}\nContent-Length: {}".format(
            item['status'], status_codes.get(item['status'], 'unknown'),
            item['content-length'])
        redirect = item.get('redirect')
        if redirect is not None:
            response += '\nLocation: {}'.format(redirect)
        self.createAndAddVulnWebToService(
            h_id,
            s_id,
            name='Path found: {} ({})'.format(item['path'], item['status']),
            desc="Dirsearch tool found the following URL: {}".format(
                url.geturl()),
            severity="info",
            method='GET',
            response=response,
            **get_vulnweb_url_fields(url.geturl()))

    def processCommandString(self, username, current_path, command_string):
        parser = argparse.ArgumentParser(conflict_handler='resolve')
        parser.add_argument('-h', '--help', action='store_true')
        parser.add_argument('--json-report')
        args, unknown = parser.parse_known_args(shlex.split(command_string))

        if args.help:
            self.devlog('help detected, ignoring parsing')
            return command_string
        if args.json_report:
            # The user already defined a path to the JSON report
            self.json_report_file = args.json_report
            self.remove_report = False
            return command_string
        else:
            # Use temporal file to save the report data
            # TODO: use tempfile
            self.json_report_file = tempfile.mktemp(
                prefix="dirsearch_report_", suffix=".json")
            self.devlog('Setting report file to {}'.format(
                self.json_report_file))
            self.remove_report = True
            return '{} --json-report {}'.format(command_string,
                                                self.json_report_file)


def createPlugin():
    return DirsearchPlugin()
