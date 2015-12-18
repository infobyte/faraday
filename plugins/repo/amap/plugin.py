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
import argparse
import shlex
import socket
import random
current_path = os.path.abspath(os.getcwd())


                                                                        
                           
                                                                     
                      

class AmapPlugin(core.PluginBase):
    """
    Example plugin to parse amap output.
    """
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id              = "Amap"
        self.name            = "Amap Output Plugin"
        self.plugin_version         = "0.0.3"
        self.version   = "5.4"
        self.options         = None
        self._current_output = None
        self._command_regex  = re.compile(r'^(amap|sudo amap).*?')
        self._hosts          = []
        self._completition = {
                                "":"amap [-A|-B|-P|-W] [-1buSRHUdqv] [[-m] -o &lt;file&gt;] [-D &lt;file&gt;] [-t/-T sec] [-c cons] [-C retries] [-p proto] [-i &lt;file&gt;] [target port [port] ...]",
                                "-A":"Map applications: send triggers and analyse responses (default)",
                                "-B":"Just grab banners, do not send triggers",
                                "-P":"No banner or application stuff - be a (full connect) port scanner",
                                "-1":"Only send triggers to a port until 1st identification. Speeeeed!",
                                "-6":"Use IPv6 instead of IPv4",
                                "-b":"Print ascii banner of responses",
                                "-i":"Nmap machine readable outputfile to read ports from",
                                "-u":"Ports specified on commandline are UDP (default is TCP)",
                                "-R":"Do NOT identify RPC / SSL services",
                                "-S":"Do NOT identify RPC / SSL services",
                                "-H":"Do NOT send application triggers marked as potentially harmful",
                                "-U":"Do NOT dump unrecognised responses (better for scripting)",
                                "-d":"Dump all responses",
                                "-v":"Verbose mode, use twice (or more!) for debug (not recommended :-)",
                                "-q":"Do not report closed ports, and do not print them as unidentified",
                                "-o":"FILE [-m] Write output to file FILE, -m creates machine readable output",
                                "-c":"CONS    Amount of parallel connections to make (default 32, max 256)",
                                "-C":"RETRIES Number of reconnects on connect timeouts (see -T) (default 3)",
                                "-T":"SEC     Connect timeout on connection attempts in seconds (default 5)",
                                "-t":"SEC     Response wait timeout in seconds (default 5)",
                                "-p":"PROTO   Only send triggers for this protocol (e.g. ftp)",
        }

        global current_path
        self._file_output_path=os.path.join(self.data_path,"amap_output-%s.txt" % random.uniform(1,10))


    def parseOutputString(self, output, debug = False):
                          
                                                                                             
        if not os.path.exists(self._file_output_path):
            return False

        if not debug:
            with open(self._file_output_path) as f:
                output = f.read()
        
        services = {}
        for line in output.split('\n'):
            if line.startswith('#'):
                         
                continue 
            
                                                                                                 
            fields = self.get_info(line)
                                                                                                 
            
            if len(fields) < 6:
                                                   
                continue

            address          = fields[0]
            h_id = self.createAndAddHost(address)

            port             = fields[1] 
            protocol         = fields[2]
            port_status      = fields[3]
                                         
            identification   = fields[5]
            printable_banner = fields[6]
                                         
            if port in services.keys():
                                      
                if identification != 'unidentified':
                                          
                    services[port][5] += ', ' + identification
            else:
                services[port] = [address, port, protocol, port_status, None, identification, printable_banner, None]
            
            
            args={}
            if self.args.__getattribute__("6"):
                self.ip = self.get_ip_6(self.args.m)
                args['ipv6_address']=address
            else:
                self.ip=self.getAddress(self.args.m)
                args['ipv4_address']=address
            
            if address != self.args.m:
                args['hostname_resolution']=self.args.m
            
            i_id = self.createAndAddInterface(h_id, name=address, **args)    

        for key in services:
            service = services.get(key)
            s_id = self.createAndAddServiceToInterface(h_id, i_id, service[5], service[2], ports = [service[1]], status = service[3],description = service[6])
        
        return True

    file_arg_re = re.compile(r"^.*(-o \s*[^\s]+\s+(?:-m|)).*$")

    def get_info(self,data):
        if self.args.__getattribute__("6"):
            f = re.search(r"^\[(.*)\]:(.*):(.*):(.*):(.*):(.*):(.*):(.*)",data)
            return [f.group(1),f.group(2),f.group(3),
                    f.group(4),f.group(5),f.group(6),f.group(7),f.group(8)] if f else []
        
        else:
            return data.split(':')
        
        
    def get_ip_6(self,host, port=0):
                                                              
         alladdr = socket.getaddrinfo(host,port)
         ip6 = filter(
             lambda x: x[0] == socket.AF_INET6,                
             alladdr
         )
                                        
                                       
         return list(ip6)[0][4][0]
                                
                    
    
    def getAddress(self, hostname):
        """
        Returns remote IP address from hostname.
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.error, msg:
                                                        
            return hostname

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -m parameter to get machine readable output.
        """
        arg_match = self.file_arg_re.match(command_string)
        
        parser = argparse.ArgumentParser()
        
        parser.add_argument('-6',action='store_true')
        parser.add_argument('-o')
        parser.add_argument('-m')
        
        
        self._output_file_path = os.path.join(self.data_path,"%s_%s_output-%s.xml" % (self.get_ws(),
                                                                                        self.id, 
                                                                                        random.uniform(1,10)))        
        
        if arg_match is None:               
            final= re.sub(r"(^.*?amap)",
                          r"\1 -o %s -m " % self._file_output_path,
                          command_string) 
        else:
            final= re.sub(arg_match.group(1),
                          r"-o %s -m " % self._file_output_path,
                          command_string)
        
                                          
        cmd=shlex.split(re.sub(r'\-h|\-\-help', r'', final))
        if "-6" in cmd:
            cmd.remove("-6")
            cmd.insert(1,"-6")
        
                        
                     
        args=None
        if len(cmd) > 4:
            try:
                args, unknown = parser.parse_known_args(cmd)
            except SystemExit:
                pass
        
        self.args=args
        return final

    def setHost(self):
        pass

def createPlugin():
    return AmapPlugin()

