#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from config.configuration import getInstanceConfiguration
from model.common import ModelObject, ModelObjectNote, ModelObjectVuln, ModelObjectVulnWeb, ModelObjectCred, ModelComposite, ModelLeaf
from model.common import Metadata
from utils.common import *  
from utils.decorators import updateLocalMetadata, save, delete

import model.api as api
try:
    import IPy
except ImportError:
    print "[-] Python module IPy was not found in the system, please install it and try again"
    print "[-] ex: sudo pip install IPy"
CONF = getInstanceConfiguration()

class Host(ModelComposite):
    """
    Represents a host found in the network.
    A hosts can have 1 or more interfaces and also 1 or more services (apps)
    Services can be reached through all host interfaces or only some of them
    The host has some attributes that are filled by the pen test tools run by
    the user
    """
                                               
    class_signature = "Host"

    def __init__(self, name, os = "Unknown", default_gateway=None, dic=None):
        ModelObject.__init__(self)
        self._interfaces            = {}
        self._applications          = {}
        self.categories             = []
        if dic is not None:
            self._fromDict(dic)
        else:
            self.__init(name, os, default_gateway)

    def __init(self, name, os = "Unknown", default_gateway=None):
        self._name = None
        if name is not None:
            self.setName(name)
        self._name = name
        self._operating_system = os if os else "Unknown"
        self._default_gateway = api.getLocalDefaultGateway() \
                                if default_gateway is None else default_gateway

    def _updatePublicAttributes(self):
                                                                           
        self.publicattrs['Operating System'] = 'getOS'
        self.publicattrsrefs['Operating System'] = '_operating_system'

    def accept(self, visitor):
        """ Accept method for visitor in the host leaf"""
        for ints in self.getAllInterfaces():
            ints.accept(visitor)
        visitor.visit(self) 

    def getCategories(self):
        return self.categories

    def getCurrentCategory(self):
                          
        cat = CONF.getDefaultCategory()
        try:
            cat = self.getCategories()[0]
        except:
            pass
        return cat

    def updateID(self): 
        self._id = get_hash([self._name])

    def setOS(self, newOS): 
        self._operating_system = newOS

    def getOS(self):
        return self._operating_system
    
    operating_system = property(getOS, setOS)

    def setName(self, newName):
                                 
        self._name = newName

    def getName(self):
        return self._name
    
    name = property(getName, setName) 

    @save
    @updateLocalMetadata
    def updateAttributes(self, name=None, description=None, os=None, owned=None):
        if name is not None:
            self.setName(name)
        if description is not None:
            self.setDescription(description)
        if os is not None:
            self.setOS(os)
        if name is not None:
            self.setOwned(owned)


    @updateLocalMetadata
    def addInterface(self, newInterface, update=False, setparent=True):
        return self._addValue("_interfaces", newInterface,
                              setparent=setparent, update=update)

    @updateLocalMetadata
    def delInterface(self, intID):
                                                                       
        interface = self.getInterface(intID)
        if interface is not None:
            for srv in interface.getAllServices():
                srv.delInterface(intID)
                                         
        return self._delValue("_interfaces", intID)

    def addInterfaceFull(self, interface):
        self.addInterface(interface)

    def getAllInterfaces(self, mode = 0):
        """
        return all interfaces in this host
        mode = 0 returns a list of interface objects
        mode = 1 returns a dictionary of interface objects with their id as key
        """
        return self._getAllValues("_interfaces", mode)

    def getInterface(self, value):
        """
        value can be mac or ip address
        if value is found it returns the interface objets
        it returns None otherwise
        """
        return self._getValueByID("_interfaces", value)


    def getService(self, name):
        """
        if name is found it returns the service object
        it returns None otherwise
        """
        service = None
        for interface in self.getAllInterfaces():
            if interface.getService(name):
                service = interface.getService(name)
                break
        return service

    @updateLocalMetadata
    def addApplication(self, newApp, update=False, setparent=True):
        return self._addValue("_applications", newApp,
                              setparent=setparent, update=update)

    @updateLocalMetadata
    def delApplication(self, appID):
                                         
        app = self.getApplication(appID)
        if app is not None:
            for srv in app.getAllServices():
                srv.delApplication(appID)
                                        
        return self._delValue("_applications", appID)

    def addApplicationFull(self, app):
        self.addApplication(app)

    def getAllApplications(self, mode = 0):
        """
        return all applications in this interface
        mode = 0 returns a list of service objects
        mode = 1 returns a dictionary of service objects with their id as key
        """
        return self._getAllValues("_applications", mode)

    def getApplication(self, name):
        """
        if name is found it returns the application object
        it returns None otherwise
        """
        return self._getValueByID("_applications", name)

    def __eq__(self, other_host):
        if isinstance(other_host, Host):
            if self._name == other_host.getName():
                return True
            else: 
                ip_addr_this = self.getIPv4Addresses()
                ip_addr_other = other_host.getIPv4Addresses()
                for addr in ip_addr_this:
                    if addr in ip_addr_other and IPy.IP(addr).iptype() == "PUBLIC":
                        return True
                                                       
        return False

    def __ne__(self, other_host): 
        return not self == other_host

    def getIPv4Addresses(self):
        """
        returns a list of all ipv4 addresses from all interfaces on this host
        """
        l = [interface.ipv4['address'] for name, interface in self._interfaces.items()]
        l.sort()
        return l

    def getIPv6Addresses(self):
        """
        returns a list of all ipv4 addresses from all interfaces on this host
        """
        l = [interface.ipv6['address'] for name, interface in self._interfaces.items()]
        l.sort()
        return l

class Interface(ModelComposite):
    """
    An interface in a host
    """
                                               
    class_signature = "Interface"

    def __init__(self, name = "", mac = "00:00:00:00:00:00",
                 ipv4_address = "0.0.0.0", ipv4_mask = "0.0.0.0",
                 ipv4_gateway = "0.0.0.0", ipv4_dns = [],
                 ipv6_address = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_prefix = "00",
                 ipv6_gateway = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns = [],
                 network_segment = "", hostname_resolution = None):

        ModelObject.__init__(self)

                              
        self._name         = name
        self.mac           = mac
        self.ipv4          = {
                                "address" : ipv4_address,
                                "mask"    : ipv4_mask,
                                "gateway" : ipv4_gateway,
                                "DNS"     : ipv4_dns
                            }
             
        self.ipv6         = {
                                "address" : ipv6_address,
                                "prefix"    : ipv6_prefix,
                                "gateway" : ipv6_gateway,
                                "DNS"     : ipv6_dns
                            }

                                                    
        self._services      = {}

                                                                      
        self.network_segment       = network_segment

                                                     
        self._hostnames=[]
        if hostname_resolution is not None:
            if isinstance(hostname_resolution, (str,unicode)):
                self._hostnames.append(hostname_resolution)
            else:
                self._hostnames = hostname_resolution

        self.amount_ports_opened   = 0
        self.amount_ports_closed   = 0
        self.amount_ports_filtered = 0

    def _updatePublicAttributes(self):
                                                                           
        self.publicattrs['MAC Address'] = 'mac'
        self.publicattrs['IPV4 Settings'] = 'ipv4'
        self.publicattrs['IPV6 Settings'] = 'ipv6'
        self.publicattrs['Network Segment'] = 'network_segment'
        self.publicattrs['Hostnames'] = 'getHostnames'
        self.publicattrs['Ports opened'] = 'amount_ports_opened'
        self.publicattrs['Ports closed'] = 'amount_ports_closed'
        self.publicattrs['Ports filtered'] = 'amount_ports_filtered'

        self.publicattrsrefs['MAC Address'] = 'mac'
        self.publicattrsrefs['IPV4 Settings'] = 'ipv4'
        self.publicattrsrefs['IPV6 Settings'] = 'ipv6'
        self.publicattrsrefs['Network Segment'] = 'network_segment'
        self.publicattrsrefs['Hostnames'] = '_hostnames'

    def defaultValues(self):
        defVals = ModelObject.defaultValues(self)
        defVals.extend([{
                                "address" :  "0.0.0.0",
                                "mask"    :  "0.0.0.0",
                                "gateway" :  "0.0.0.0",
                                "DNS"     :  []
                                }, {'prefix': '00', 'gateway': '0000:0000:0000:0000:0000:0000:0000:0000', 'DNS': [], 'address': '0000:0000:0000:0000:0000:0000:0000:0000'}])
        return defVals

    def accept(self, visitor):
        for servs in self.getAllServices():
            servs.accept(visitor)
        visitor.visit(self) 

    
    def tieBreakable(self, property_key):
        if property_key in ["_hostnames"]:
            return True
        return False

    def tieBreak(self, key, prop1, prop2):
        if key == "_hostnames":
            prop1.extend(prop2)
            return list(set(prop1))
        return None

    def updateID(self):
                                                                                                          
        self._id = get_hash([self.network_segment, self.ipv4["address"], self.ipv6["address"]])

    def setName(self, name):
        self._name = name
    
    def getName(self):
        return self._name
    
                                      

    def setMAC(self, mac):
        self.mac = mac
        
    def getMAC(self):
        return self.mac 
    
    def setNetworkSegment(self, network_segment):
        self.network_segment = network_segment
    
    def getNetworkSegment(self):
        return self.network_segment 
    
    def setIPv4(self, ipv4):
        self.ipv4["address"] = ipv4["address"]
        self.ipv4["mask"] = ipv4["mask"]
        self.ipv4["gateway"] = ipv4["gateway"]
        self.ipv4["DNS"] = ipv4["DNS"]
    
    def getIPv4(self):
        return self.ipv4

    def getIPv4Address(self):
        return self.ipv4["address"]

    def getIPv4Mask(self):
        return self.ipv4["mask"]

    def getIPv4Gateway(self):
        return self.ipv4["gateway"]

    def getIPv4DNS(self):
        return self.ipv4["DNS"]
    
    def setIPv6(self, ipv6):
        self.ipv6["address"] = ipv6["address"]
        self.ipv6["prefix"] = ipv6["prefix"]
        self.ipv6["gateway"] = ipv6["gateway"]
        self.ipv6["DNS"] = ipv6["DNS"]
    
    def getIPv6(self):
        return self.ipv6

    def getIPv6Address(self):
        return self.ipv6["address"]

    def getIPv6Prefix(self):
        return self.ipv6["prefix"]

    def getIPv6Gateway(self):
        return self.ipv6["gateway"]

    def getIPv6DNS(self):
        return self.ipv6["DNS"]
    
    def setPortsOpened(self, ports_opened):
        self.amount_ports_opened   = ports_opened
    
    def getPortsOpened(self):
        return self.amount_ports_opened 
    
    def setPortsClosed(self, ports_closed):
        self.amount_ports_closed   = ports_closed
        
    def getPortsClosed(self):
        return self.amount_ports_closed 
    
    def setPortsFiltered(self, ports_filtered):
        self.amount_ports_filtered = ports_filtered
        
    def getPortsFiltered(self):
        return self.amount_ports_filtered

    @updateLocalMetadata
    def addService(self, newService, update=False, setparent=True):
        res = self._addValue("_services", newService, setparent=setparent, update=update)    
        if res: newService.addInterface(self)
        return res

    @updateLocalMetadata
    def delService(self, srvID, checkFullDelete=True):
        res = True
        res = self._delValue("_services", srvID)
        return res

    def getAllServices(self, mode = 0):
        """
        return all services in this interface
        mode = 0 returns a list of service objects
        mode = 1 returns a dictionary of service objects with their id as key
        """
        return self._getAllValues("_services", mode)

    def getService(self, name):
        """
        if name is found it returnsnetwork_segment the service object
        it returns None otherwise
        """
        return self._getValueByID("_services", name)

    def addHostname(self, hostname):
        if hostname not in self._hostnames:
            self._hostnames.append(hostname)

    def removeHostname(self, hostname):
        if hostname in self._hostnames:
            self._hostnames.remove(hostname)

    def getHostnames(self):
        return self._hostnames
    
    def setHostnames(self, hostnames):
        self._hostnames = hostnames

    @save
    @updateLocalMetadata
    def updateAttributes(self, name=None, description=None, hostnames=None, mac=None, ipv4=None, ipv6=None,
                         network_segment=None, amount_ports_opened=None, amount_ports_closed=None,
                         amount_ports_filtered=None, owned=None):
        if name is not None:
            self.setName(name)
        if description is not None:
            self.setDescription(description)
        if hostnames is not None:
            self.setHostnames(hostnames)
        if mac is not None:
            self.setMAC(mac)
        if ipv4 is not None:
            self.setIPv4(ipv4)
        if ipv6 is not None:
            self.setIPv6(ipv6)
        if network_segment is not None:
            self.setNetworkSegment(network_segment)
        if amount_ports_opened is not None:
            self.setPortsOpened(amount_ports_opened)
        if amount_ports_closed is not None:
            self.setPortsClosed(amount_ports_closed)
        if amount_ports_filtered is not None:
            self.setPortsFiltered(amount_ports_filtered)


class Service(ModelComposite):
    """
    A service or application running in a host
    Commonly a service will have a name or description, a set of ports in which
    is listening and also a particular version
    """
                                               
    class_signature = "Service"

    def __init__(self, name, protocol="TCP", ports=None, status="running",
                 version="unknown", description = ""):
        ModelComposite.__init__(self)

        self._name          = name
        self.description    = description
        self.setProtocol(protocol)
        self._ports=[]
        self.setPorts(ports)
        self._status        = status
        self._version       = version
        self._interfaces    = {}
        self._applications  = {}
        self._creds = {}

    def _updatePublicAttributes(self):
                                                                           
        self.publicattrsrefs['Ports'] = '_ports'
        self.publicattrsrefs['Protocol'] = '_protocol'
        self.publicattrsrefs['Status'] = '_status'
        self.publicattrsrefs['Version'] = '_version'

        self.publicattrs['Ports'] = 'getPorts'
        self.publicattrs['Protocol'] = 'getProtocol'
        self.publicattrs['Status'] = 'getStatus'
        self.publicattrs['Version'] = 'getVersion'


    def setName(self, name):
        self._name = name
    
    def getName(self):
        return self._name


    def setProtocol(self, protocol):
        self._protocol = protocol.lower()

    def getProtocol(self):
        return self._protocol

    def addPort(self, port):
        if port not in self._ports:
            self._ports.append(port)

    def removePort(self, port):
        if port in self._ports:
            self._ports.remove(port)

    def getPorts(self):
        return self._ports
    
    def setPorts(self, ports):
        if ports is not None:
            if isinstance(ports, (str,unicode)):
                self._ports = [int(ports)]
            elif isinstance(ports, int):
                self._ports = [ports]
            elif isinstance(ports, list):
                self._ports = [int(p) for p in ports]
            else:
                api.devlog("ports must be a string, an int o a list of any of those types")


    def setStatus(self, status):
        self._status = status

    def getStatus(self):
        return self._status

    def setVersion(self, version):
        self._version = version

    def getVersion(self):
        return self._version 

    def updateID(self): 
        self._id = get_hash([self._protocol, ":".join(str(self._ports))])

    @save
    @updateLocalMetadata
    def updateAttributes(self, name=None, description=None, protocol=None, ports=None, 
                          status=None, version=None, owned=None):
        if name is not None:
            self.setName(name)
        if description is not None:
            self.setDescription(description)
        if protocol is not None:
            self.setProtocol(protocol) 
        if ports is not None:
            self.setPorts(ports)
        if status is not None:
            self.setStatus(status)
        if version is not None:
            self.setVersion(version)
        if owned is not None:
            self.setOwned(owned) 

    def addInterface(self, newInterface, update=False, setparent=False):
        res = self._addValue("_interfaces", newInterface, update=update, setparent=setparent)
                                                                                 
        if res: newInterface.addService(self)
        return res

    def delInterface(self, intID, checkFullDelete=True):
        interface = self.getInterface(intID)
        res = self._delValue("_interfaces", intID)
        if res:
            if interface is not None:
                interface.delService(self.getID(), checkFullDelete)

        if checkFullDelete: self._checkFullDelete()
        return res

    def _checkFullDelete(self):
        api.devlog("Doing service checkFullDelete")
        if not self._interfaces and not self._applications:
            if self.getParent() is not None:
                self.getParent().delService(self.getID())

    def getAllInterfaces(self, mode = 0):
        """
        return all interfaces in this host
        mode = 0 returns a list of interface objects
        mode = 1 returns a dictionary of interface objects with their id as key
        """
        return self._getAllValues("_interfaces", mode)

    def getInterface(self, value):
        """
        value can be a mac or ipv4 address
        if value is found it returns the interface objets
        it returns None otherwise
        """
        return self._getValueByID("_interfaces", value)

    def addApplication(self, newApp, update=False):
        res = self._addValue("_applications", newApp, update=update)
        if res: newApp.addService(self)
        return res

    def delApplication(self, appID, checkFullDelete=True):
        app = self.getApplication(appID)
        res = self._delValue("_applications", appID)
        if res:
            if app is not None:
                app.delService(self.getID(), checkFullDelete)

        if checkFullDelete: self._checkFullDelete()
        return res

    def getAllApplications(self, mode = 0):
        """
        return all applications in this service
        mode = 0 returns a list of applications objects
        mode = 1 returns a dictionary of application objects with their id as key
        """
        return self._getAllValues("_applications", mode)

    def getApplication(self, name):
        """
        if name is found it returns the application object
        it returns None otherwise
        """
        return self._getValueByID("_applications", name)

class HostApplication(ModelLeaf):
    """
    An application running in a host
    The application can be related to more than one service
    Commonly this will have a name, description, version and status
    """
                                               
    class_signature = "HostApplication"

    def __init__(self, name, status = "running", version = "unknonw"):
        ModelObject.__init__(self)

        self._name          = name
        self._status        = status
        self._version       = version
                                                    
        self._services      = {}

    def _updatePublicAttributes(self): 
        self.publicattrs['Status'] = 'getStatus'
        self.publicattrs['Version'] = 'getVersion'

    def setName(self, name):
        self._name = name
    
    def getName(self):
        return self._name 
    
    def setStatus(self, status):
        self._status = status

    def getStatus(self):
        return self._status

    def setVersion(self, version):
        self._version = version

    def getVersion(self):
        return self._version

    def updateID(self):
        self._id = get_hash([self._name, self._version])
    
    @updateLocalMetadata
    def updateAttributes(self, name=None, description=None, status=None, version=None, owned=None):
        if name is not None:
            self.setName(name)
        if description is not None:
            self.setDescription(description)
        if status is not None:
            self.setStatus(status)
        if version is not None:
            self.setVersion(version)
        if owned is not None:
            self.setOwned(owned)

    @updateLocalMetadata
    def addService(self, newService, update=False):
        res = self._addValue("_services", newService, update=update)
        if res: newService.addApplication(self)
        if self.getParent() is not None:
            self.getParent().addService(newService)
        return res

    @updateLocalMetadata
    def delService(self, srvID, checkFullDelete=True):
        srv = self.getService(srvID)
        res = self._delValue("_services", srvID)
        if res:
            if srv is not None:
                srv.delApplication(self.getID(), checkFullDelete)
        return res

    def getAllServices(self, mode = 0):
        """
        return all services in this interface
        mode = 0 returns a list of service objects
        mode = 1 returns a dictionary of service objects with their id as key
        """
        return self._getAllValues("_services", mode)

    def getService(self, name):
        """
        if name is found it returns the service object
        it returns None otherwise
        """
        return self._getValueByID("_services", name)


def __checkDiffObjectClasses(objLeft, objRight, checkClass):
                                                  
    if not isinstance(objLeft, checkClass) or not isinstance(objRight, checkClass) :
        raise Exception("Cannot diff objects. Class mismatch!. objLeft class (%s) - objRight class (%s)"
                        % (objLeft.__class__.__name__, objRight.__class__.__name__))

def HostDiff(objLeft, objRight):
    """
    
    """
    __checkDiffObjectClasses(objLeft, objRight, Host)


def InterfaceDiff(objLeft, objRight):
    __checkDiffObjectClasses(objLeft, objRight, Interface)
    pass

def ServiceDiff(objLeft, objRight):
    __checkDiffObjectClasses(objLeft, objRight, Service)
    pass

def HostApplicationDiff(objLeft, objRight):
    __checkDiffObjectClasses(objLeft, objRight, HostApplication)
    pass

__diff_dispatch_table = {
    Host: HostDiff,
    HostApplication: HostApplicationDiff,
    Interface: InterfaceDiff,
    Service: ServiceDiff    
}

                                                         
def ModelObjectDiff(objLeft, objRight):
    """
    This is like a dispatcher. Based on the object class it call the corresponding
    diff function. If a diff function for the class is not pressent it raises a
    NotImplemented Exception
    """
                                                         
    if not isinstance(objLeft, objRight.__class__):
        raise Exception("Cannot compare objects of different classes. objLeft (%s) vs objRight (%s)"
                        % (objLeft.__class__.__name__, objRight.__class__.__name__))
    
    global __diff_dispatch_table    
    diff_func = __diff_dispatch_table.get(objLeft.__class__, None)

    if diff_func is None:
        raise NotImplemented("Diff function for %s does not exist" % objLeft.__class__.__name__)
    
    return diff_func(objLeft, objRight)    
