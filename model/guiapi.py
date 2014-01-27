#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from model.common import factory
from config.configuration import getInstanceConfiguration
from model.api import showDialog, showPopup

CONF = getInstanceConfiguration()

                                                                      
                
                                                                      
showDialog = showDialog
showPopup = showPopup

__the_mainapp = None
                                                                         
__model_controller = None

def setMainApp(ref):
    global __the_mainapp
    __the_mainapp = ref
    
def getMainApp():
    global __the_mainapp
    return __the_mainapp

def getMainWindow():
    global __the_mainapp
    return __the_mainapp.getMainWindow()
    
def postCustomEvent(event, receiver=None):
    if receiver is None:
        receiver = getMainWindow()
    __the_mainapp.qapp.postEvent(receiver, event)
    
def sendCustomEvent(event, receiver=None):
    if receiver is None:
        receiver = getMainWindow()
    __the_mainapp.qapp.sendEvent(receiver, event)

def setUpGUIAPIs(controller):
    global __model_controller
    __model_controller = controller
    
                                                                                
                                                 
                                                                                
def registerWidget(widget):
    if widget is not None:
        __model_controller.registerWidget(widget)

def deregisterWidget(widget):
    if widget is not None:
        __model_controller.deregisterWidget(widget)
        
                                                                                
                                          
                                                                                


def createAndAddHost(name, os = "Unknown", category=None, update = False, old_hostname = None ):

    host = newHost(name, os)
    if addHost(host, category, update, old_hostname):
        return host.getID()
    return None

def createAndAddInterface(host_id, name = "", mac = "00:00:00:00:00:00",
                 ipv4_address = "0.0.0.0", ipv4_mask = "0.0.0.0",
                 ipv4_gateway = "0.0.0.0", ipv4_dns = [],
                 ipv6_address = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_prefix = "00",
                 ipv6_gateway = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns = [],
                 network_segment = "", hostname_resolution = []):
    """
    Creates a new interface object with the parameters provided and adds it to
    the host selected.
    If interface is successfuly created and the host exists, it returns the inteface id
    It returns None otherwise
    """
    interface = newInterface(name, mac, ipv4_address, ipv4_mask, ipv4_gateway,
                             ipv4_dns, network_segment, hostname_resolution)
    if addInterface(host_id, interface):
        return interface.getID()
    return None

def createAndAddApplication(host_id, name, status = "running", version = "unknown"):
    application = newApplication(name, status, version)
    if addApplication(host_id, application):
        return application.getID()
    return None

def createAndAddServiceToApplication(host_id, application_id, name, protocol = "tcp?", 
                ports = [], status = "running", version = "unknown", description = ""):
    service = newService(name, protocol, ports, status, version, description)
    if addServiceToApplication(host_id, application_id, service):
        return service.getID()
    return None

def createAndAddServiceToInterface(host_id, interface_id, name, protocol = "tcp?", 
                ports = [], status = "running", version = "unknown", description = ""):
    service = newService(name, protocol, ports, status, version, description)
    if addServiceToInterface(host_id, interface_id, service):
        return service.getID()
    return None

               

def createAndAddVulnToHost(host_id, name, desc, ref, severity="0"):
    vuln = newVuln(name, desc, ref, severity)
    if addVulnToHost(host_id, vuln):
        return vuln.getID()
    return None

def createAndAddVulnToInterface(host_id, interface_id, name, desc, ref, severity="0"):
    vuln = newVuln(name, desc, ref, severity)
    if addVulnToInterface(host_id, interface_id, vuln):
        return vuln.getID()
    return None
    
def createAndAddVulnToApplication(host_id, application_id, name, desc, ref, severity="0"):
    vuln = newVuln(name, desc, ref, severity)
    if addVulnToApplication(host_id, application_id, vuln):
        return vuln.getID()
    return None

def createAndAddVulnToService(host_id, service_id, name, desc, ref, severity="0"):
                                                                                   
    vuln = newVuln(name, desc, ref, severity)
    if addVulnToService(host_id, service_id, vuln):
        return vuln.getID()
    return None

def createAndAddVulnWebToService(host_id, service_id, name, desc, website, path, ref=None, severity="0", request=None, response=None,
                method=None,pname=None, params=None,query=None,category=None):
                                                                                   
    vuln = newVulnWeb(name, desc, website, path, ref, severity, request, response,
                method,pname, params,query,category)
    
    if addVulnToService(host_id, service_id, vuln):
        return vuln.getID()
    return None

def createAndAddVuln(model_object, name, desc, ref=None, severity="0"):
    vuln = newVuln(name, desc, ref, severity)
    if addVuln(model_object, vuln):
        return vuln.getID()
    return None

def createAndAddVulnWeb(model_object, name, desc, website, path, ref=None, severity="0", request=None, response=None,
                method=None,pname=None, params=None,query=None,category=None):
    vuln = newVulnWeb(name, desc, website, path, ref, severity, request, response,
                method,pname, params,query,category)
    if addVuln(model_object, vuln):
        return vuln.getID()
    return None

      
 
def createAndAddNoteToHost(host_id, name, text):
    note = newNote(name, text)
    if addNoteToHost(host_id, note):
        return note.getID()
    return None

def createAndAddNoteToInterface(host_id, interface_id, name, text):
    note = newNote(name, text)
    if addNoteToInterface(host_id, interface_id, note):
        return note.getID()
    return None

def createAndAddNoteToApplication(host_id, application_id, name, text):
    note = newNote(text)
    if addNoteToApplication(host_id, application_id, note):
        return note.getID()
    return None

def createAndAddNoteToService(host_id, service_id, name, text):
    note = newNote(name, text)
    if addNoteToService(host_id, service_id, note):
        return note.getID()
    return None

def createAndAddNote(model_object, name, text):
    note = newNote(name, text)
    if addNote(model_object, note):
        return note.getID()
    return None

      
def createAndAddCred(model_object, username, password):
    cred = newCred(username, password)
    if addCred(model_object, cred):
        return cred.getID()
    return None

def createAndAddCredToHost(host_id, username, password):
    cred = newCred(username, password)
    if addCredToHost(host_id, cred):
        return cred.getID()
    return None

def createAndAddCredToService(host_id, service_id, username, password):
    cred = newCred(username, password)
    if addCredToService(host_id, service_id, cred):
        return cred.getID()
    return None
                                                                                
                                                 
                                                                                

                                                                                             

def addHost(host, category=None, update = False, old_hostname = None):
    if host is not None:
        __model_controller.addHostSYNC(host, category, update, old_hostname)
        return True
    return False

def addInterface(host_id, interface):
    if interface is not None:
        __model_controller.addInterfaceSYNC(host_id, interface)
        return True
    return False

def addApplication(host_id, application):
    if application is not None:
        __model_controller.addApplicationSYNC(host_id, application)
        return True
    return False

def addServiceToApplication(host_id, application_id, service):
    if service is not None:
        __model_controller.addServiceToApplicationSYNC(host_id, application_id, service)
        return True
    return False

def addServiceToInterface(host_id, interface_id, service):
    if service is not None:
        __model_controller.addServiceToInterfaceSYNC(host_id, interface_id, service)
        return True
    return False

               

def addVulnToHost(host_id, vuln):
    if vuln is not None:
        __model_controller.addVulnToHostSYNC(host_id, vuln)
        return True
    return False

def addVulnToInterface(host_id, interface_id, vuln):
    if vuln is not None:
        __model_controller.addVulnToInterfaceSYNC(host_id, interface_id, vuln)
        return True
    return False

def addVulnToApplication(host_id, application_id, vuln):
    if vuln is not None:
        __model_controller.addVulnToApplicationSYNC(host_id, application_id, vuln)
        return True
    return False

def addVulnToService(host_id, service_id, vuln):
    if vuln is not None:
        __model_controller.addVulnToServiceSYNC(host_id, service_id, vuln)
        return True
    return False

def addVuln(model_object, vuln):
    if vuln is not None:
        __model_controller.addVulnSYNC(model_object, vuln)
        return True
    return False

       

def addNoteToHost(host_id, note):
    if note is not None:
        __model_controller.addNoteToHostSYNC(host_id, note)
        return True
    return False

def addNoteToInterface(host_id, interface_id, note):
    if note is not None:
        __model_controller.addNoteToInterfaceSYNC(host_id, interface_id, note)
        return True
    return False

def addNoteToApplication(host_id, application_id, note):
    if note is not None:
        __model_controller.addNoteToApplicationSYNC(host_id, application_id, note)
        return True
    return False

def addNoteToService(host_id, service_id, note):
    if note is not None:
        __model_controller.addNoteToServiceSYNC(host_id, service_id, note)
        return True
    return False

def addNote(model_object, note):
    if note is not None:
        __model_controller.addNoteSYNC(model_object, note)
        return True
    return False

      
def addCred(model_object, cred):
    if cred is not None:
        __model_controller.addCredSYNC(model_object, cred)
        return True
    return False

def addCredToService(host_id, service_id, cred):
    if cred is not None:
        __model_controller.addCredToServiceSYNC(host_id, service_id, cred)
        return True
    return False

def addCredToHost(host_id, cred):
    if cred is not None:
        __model_controller.addCredToHostSYNC(host_id, cred)
        return True
    return False

                                                                                
                                  
                                                                                
                                         
def delHost(host_id):
    __model_controller.delHostSYNC(host_id)
    return True

def delApplication(host_id, application_id):
    __model_controller.delApplicationSYNC(host_id, application_id)
    return True

def delInterface(host_id, interface_id):
    __model_controller.delInterfaceSYNC(host_id, interface_id)
    return True

def delServiceFromHost(host_id, service_id):
    __model_controller.delServiceFromHostSYNC(host_id, service_id)
    return True

def delServiceFromInterface(host_id, interface_id, service_id):
    __model_controller.delServiceFromInterfaceSYNC(host_id, interface_id, service_id)
    return True

def delServiceFromApplication(host_id, application_id, service_id):
    __model_controller.delServiceFromApplicationSYNC(host_id, application_id, service_id)
    return True

               
                                                                                
def delVulnFromApplication(vuln, hostname, appname):
    __model_controller.delVulnFromApplicationSYNC(hostname, appname, vuln)
    return True
                                                                                
def delVulnFromInterface(vuln, hostname, intname):
    __model_controller.delVulnFromInterfaceSYNC(hostname,intname, vuln)
    return True
                                                                                
def delVulnFromHost(vuln, hostname):
    __model_controller.delVulnFromHostSYNC(hostname,vuln)
    return True

                                                                                
def delVulnFromService(vuln, hostname, srvname):
    __model_controller.delVulnFromServiceSYNC(hostname,srvname, vuln)
    return True

def delVuln(model_object, vuln_id):
    __model_controller.delVulnSYNC(model_object, vuln_id)
    return True

       
                                                                                
def delNoteFromApplication(note, hostname, appname):
    __model_controller.delNoteFromApplicationSYNC(hostname, appname, note)
    return True
                                                                                
def delNoteFromInterface(note, hostname, intname):
    __model_controller.delNoteFromInterfaceSYNC(hostname,intname, note)
    return True
                                                                                
def delNoteFromHost(note, hostname):
    __model_controller.delNoteFromHostSYNC(hostname, note)
    return True

                                                                                
def delNoteFromService(note, hostname, srvname):
    __model_controller.delNoteFromServiceSYNC(hostname,srvname, note)
    return True

def delNote(model_object, note_id):
    __model_controller.delNoteSYNC(model_object, note_id)
    return True

     
def delCred(model_object, cred_id):
    __model_controller.delCredSYNC(model_object, cred_id)
    return True

def delCredFromHost(cred, hostname):
    __model_controller.delCredFromHostSYNC(hostname, cred)
    return True

                                                                                
def delCredFromService(cred, hostname, srvname):
    __model_controller.delCredFromServiceSYNC(hostname,srvname, cred)
    return True


                                                                                
              

def editHost(host, name=None, description=None, os=None, owned=None):
    __model_controller.editHostSYNC(host, name, description, os, owned)
    return True

def editService(service, name=None, description=None, protocol=None, ports=None, status=None, version=None, owned=None):
    __model_controller.editServiceSYNC(service, name, description, protocol, ports, status, version, owned)
    return True

def editApplication(application, name, description, status, version, owned):
    __model_controller.editApplicationSYNC(application, name, description, status, version, owned)
    return True

def editInterface(interface, name=None, description=None, hostnames=None, mac=None, ipv4=None, ipv6=None, network_segment=None, 
                  amount_ports_opened=None, amount_ports_closed=None, amount_ports_filtered=None, owned=None):
    __model_controller.editInterfaceSYNC(interface, name, description, hostnames, mac, ipv4, ipv6, network_segment, 
                  amount_ports_opened, amount_ports_closed, amount_ports_filtered, owned)
    return True

def editNote(note, name=None, text=None):
    __model_controller.editNoteSYNC(note, name, text)
    return True

def editVuln(vuln, name=None, desc=None, severity=None, refs=None):
    __model_controller.editVulnSYNC(vuln, name, desc, severity, refs)
    return True

def editVulnWeb(vuln, name=None, desc=None, website=None, path=None, refs=None, severity=None, request=None, response=None,
                method=None,pname=None, params=None,query=None,category=None):
    __model_controller.editVulnWebSYNC(vuln, name, desc, website, path, refs, severity, request, response,
                method,pname, params,query,category)
    return True

def editCred(cred, username=None, password=None):
    __model_controller.editCredSYNC(cred, username, password)
    return True

                                                                                

                                                                                
               
                                                                                
def newHost(name, os = "Unknown"):
    """
    It creates and returns a Host object.
    The object created is not added to the model.
    """
                                                                           
    return factory.createModelObject("Host", name, os=os)

                                                                                
def newInterface(name = "", mac = "00:00:00:00:00:00",
                 ipv4_address = "0.0.0.0", ipv4_mask = "0.0.0.0",
                 ipv4_gateway = "0.0.0.0", ipv4_dns = [],
                 ipv6_address = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_prefix = "00",
                 ipv6_gateway = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns = [],
                 network_segment = "", hostname_resolution = []):
    """
    It creates and returns an Interface object.
    The created object is not added to the model.
    """
    return factory.createModelObject("Interface", name, mac = mac,
                 ipv4_address = ipv4_address , ipv4_mask = ipv4_mask,
                 ipv4_gateway = ipv4_gateway, ipv4_dns = ipv4_dns,
                 ipv6_address = ipv6_address , ipv6_prefix = ipv6_prefix,
                 ipv6_gateway = ipv6_gateway, ipv6_dns = ipv6_dns,
                 network_segment = network_segment,
                 hostname_resolution = hostname_resolution)
                                                                                
def newService(name, protocol = "tcp?", ports = [], status = "running",
               version = "unknown", description = ""):
    """
    It creates and returns a Service object.
    The created object is not added to the model.
    """
    return factory.createModelObject("Service",name,
                             protocol = protocol, ports = ports,
                             status = status, version = version,
                             description = description)
                                                                                

def newVuln(name, desc="", ref = None, severity=""):
    """
    It creates and returns a Vulnerability object.
    The created object is not added to the model.
    """
    return factory.createModelObject("Vulnerability", name, desc=desc,
                                                  ref=ref, severity=severity)
 
                                                                                

def newVulnWeb(name, desc="", website="", path="", ref=None, severity="", request="", response="",
                method="",pname="", params="",query="",category=""):
    """
    It creates and returns a Vulnerability object.
    The created object is not added to the model.
    """
    return factory.createModelObject("VulnerabilityWeb", name, desc=desc, ref=ref,severity=severity, website=website, path=path, request=request,
                                                  response=response,method=method,pname=pname, params=params,query=query,category=category )
 
                                                                                
   
def newNote(name,text):
    
    """
    It creates and returns a Note object.
    The created object is not added to the model.
    """
    return factory.createModelObject("Note", name, text=text)


   
def newCred(username,password):
    
    """
    It creates and returns a Cred object.
    The created object is not added to the model.
    """
    return factory.createModelObject("Cred", username, password=password)


                                                                                
def newApplication(name, status = "running", version = "unknown"):
    """
    It creates and returns an Application object.
    The created object is not added to the model.
    """
    return factory.createModelObject("HostApplication",name,
                             status = status,
                             version = version)

                                                                                

                     
  
def resolveConflicts():
    __model_controller.resolveConflicts()

def resolveConflict(conflict, kwargs):
    __model_controller.resolveConflict(conflict, kwargs)

def merge(host1, host2):
    return __model_controller.merge(host1, host2)
