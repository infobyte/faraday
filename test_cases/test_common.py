#!/usr/bin/python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from server.models import Host, Interface, Service, Vulnerability
import random
def new_random_workspace_name():
    return ("aworkspace" + "".join(random.sample([chr(i) for i in range(65, 90)
                                ], 10 ))).lower()

def create_host(self, host_name="pepito", os="linux"):
    host = Host(host_name, os)
    self.model_controller.addHostSYNC(host)
    return host

def create_interface(self, host, iname="coqiuto", mac="00:03:00:03:04:04"):
    interface = Interface(name=iname, mac=mac)
    self.model_controller.addInterfaceSYNC(host.getName(), interface)
    return interface

def create_service(self, host, interface, service_name = "coquito"):
    service = Service(service_name)
    self.model_controller.addServiceToInterfaceSYNC(host.getID(),
                                interface.getID(), service)
    return service

def create_host_vuln(self, host, name, desc, severity):
    vuln = Vulnerability(name, desc, severity)
    self.model_controller.addVulnToHostSYNC(host.getID(), vuln)

    return vuln

def create_int_vuln(self, host, interface, name, desc, severity):
    vuln = Vulnerability(name=name, description=desc, severity=severity)
    self.model_controller.addVulnToInterfaceSYNC(host.getID(), interface.getID(), vuln)

    return vuln

def create_serv_vuln(self, host, service, name, desc, severity):
    vuln = Vulnerability(name=name, description=desc, severity=severity)
    self.model_controller.addVulnToServiceSYNC(host.getID(), service.getID(), vuln)

    return vuln
