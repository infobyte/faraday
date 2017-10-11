#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from __future__ import with_statement
import re
import os
import random
from collections import defaultdict

from plugins import core


current_path = os.path.abspath(os.getcwd())


class LynisLogDataExtracter():
    def __init__(self, datfile=None, output=None):
        self.services = defaultdict(list)
        if datfile and not os.path.exists(datfile):
            with open(datfile) as f:
                self.rawcontents = f.read()

        if output:
            self.rawcontents = output

    def _svcHelper(self, ip, port, protocol, name):
        self.services[ip].append({'port': port, 'protocol': protocol, 'name': name})

    def hostname(self):
        m = re.search('^hostname=(.+)$', self.rawcontents, re.MULTILINE)
        return(m.group(1).strip())

    def osfullname(self):
        m = re.search('^os_fullname=(.+)$', self.rawcontents, re.MULTILINE)
        return(m.group(1).strip())

    def interfaces(self):
        interfaces = []
        m = re.findall('^network_interface\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        for iname in m:
            # Yeah, lynis doesnt relate interface to mac to ip...
            interfaces.append(iname)
        return(interfaces)

    def macs(self):
        macs = []
        m = re.findall('^network_mac_address\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        for mac in m:
            macs.append(mac)
        return(macs)

    def ipv4(self):
        ipv4addrs = []
        m = re.findall('^network_ipv4_address\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        for ipv4 in m:
            ipv4addrs.append(ipv4)
        return(ipv4addrs)

    def ipv6(self):
        ipv6addrs = []
        m = re.findall('^network_ipv6_address\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        for ipv6 in m:
            ipv6addrs.append(ipv6)
        return(ipv6addrs)

    def kernelVersion(self):
        m = re.search('^os_kernel_version_full=(.+)$',
                      self.rawcontents, re.MULTILINE)
        return(m.group(1).strip())

    def listeningservices(self):
        m = re.findall('^network_listen_port\[\]=(.+)$',
                       self.rawcontents, re.MULTILINE)
        for combo in m:
            x = combo.split('|')
            c = x[0].count(':')
            if c == 1:
                ip, port = x[0].split(':')
            elif c == 3:
                a, b, c, port = x[0].split(':')
                ip = '::'
            elif c == 5:
                a, b, c, d, e, port = x[0].split(':')
                ip = x[0].replace(':{}'.format(port), '')
            protocol = x[1]
            name = x[2]
            if name == '-':
                name = 'unknown'
            self._svcHelper(ip, port, protocol, name)
        return(self.services)

    def suggestions(self):
        sugs = {}
        m = re.findall('^suggestion\[\]=(.+)$', self.rawcontents, re.MULTILINE)
        for combo in m:
            x = combo.split('|')
            sugs[x[0]] = x[1]
        return(sugs)

    def warnings(self):
        warns = {}
        m = re.findall('^warning\[\]=(.+)$', self.rawcontents, re.MULTILINE)
        for combo in m:
            x = combo.split('|')
            warns[x[0]] = x[1]
        return(warns)


class LynisPlugin(core.PluginBase):
    """ Simple example plugin to parse lynis' lynis-report.dat file."""

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Lynis"
        self.name = "Lynis DAT Output Plugin"
        self.plugin_version = "0.0.3"
        self.version = "2.5.5"
        self.options = None
        self._current_output = None
        rr = r'^(lynis|sudo lynis|\.\/lynis|sudo \.\/lynis).*?'
        self._command_regex = re.compile(rr)
        self._hosts = []

        global current_path
        pp = "lynis_output-%s.txt" % random.uniform(1, 10)
        self._file_output_path = os.path.join(self.data_path, pp)

    def parseOutputString(self, output, debug=False):
        datpath = self.getDatPath(output)
        if datpath:
            lde = LynisLogDataExtracter(datfile=datpath)
        elif '# Lynis Report' in output:
            lde = LynisLogDataExtracter(output=output)

        h_id = self.createAndAddHost(name=lde.hostname(),
                                     os=lde.osfullname())

        self.createAndAddVulnToHost(
            host_id=h_id,
            name="Kernel Version",
            severity='info',
            desc=lde.kernelVersion()
        )
        interfaces = lde.interfaces()
        macs = lde.macs()
        ipv4s = lde.ipv4()
        ipv6s = lde.ipv6()
        svcs = lde.listeningservices()

        for ipv4 in ipv4s:
            i_id = self.createAndAddInterface(host_id=h_id,
                                              ipv4_address=ipv4)
            for service_data in svcs[ipv4]:
                self.createAndAddServiceToInterface(host_id=h_id,
                                                interface_id=i_id,
                                                name=service_data['name'],
                                                protocol=service_data['protocol'],
                                                ports=svcs[service_data['port']])
        for ipv6 in ipv6s:
            i_id = self.createAndAddInterface(host_id=h_id,
                                              ipv6_address=ipv6)
            for service_data in svcs[ipv6]:
                self.createAndAddServiceToInterface(host_id=h_id,
                                                interface_id=i_id,
                                                name=service_data['name'],
                                                protocol=service_data['protocol'],
                                                ports=svcs[service_data['port']])
        sugs = lde.suggestions()
        for sug in sugs:
            self.createAndAddVulnToHost(
                host_id=h_id,
                name=sug,
                severity='med',
                desc=sugs[sug]
            )

        warns = lde.warnings()
        for warn in warns:
            self.createAndAddVulnToHost(
                host_id=h_id,
                name=sug,
                severity='high',
                desc=warns[warn]
            )

    def processCommandString(self, username, current_path, command_string):
        """
        Lynis does not have a means to specify the location for the
        DAT file, which by default goes to /var/log/lynis-report.dat
        or /tmp/lynis-report.dat, depending on privileges.
        Because of that, we will extract the DAT location off
        lynis' output via parseOutputString().
        """
        pass

    def getDatPath(self, output):
        m = re.search('(\/.+\.dat)$', output, re.MULTILINE)
        if m:
            return(m.group(0).strip())


def createPlugin():
    return LynisPlugin()
