#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import socket
import zipfile
import logging

import model.common
from config.configuration import getInstanceConfiguration
#from workspace import Workspace
import model.log
from utils.logs import getLogger
from utils.common import *
import shutil
#from plugins.api import PluginControllerAPI

CONF = getInstanceConfiguration()

# global reference only for this module to work with the model controller
__model_controller = None

__workspace_manager = None

_xmlrpc_api_server = None
_plugin_controller_api = None

#XXX: temp way to replicate info
_remote_servers_proxy = []

_remote_sync_server_proxy = None

# name of the currently logged user
__current_logged_user = ""


def setUpAPIs(controller, workspace_manager, hostname=None, port=None):
    global __model_controller
    __model_controller = controller
    global __workspace_manager
    __workspace_manager = workspace_manager
    _setUpAPIServer(hostname, port)


def startAPIServer():
    global _xmlrpc_api_server
    if _xmlrpc_api_server is not None:
        devlog("starting xmlrpc api server...")
        #_xmlrpc_api_server.serve_forever()
        _xmlrpc_api_server.start()


def stopAPIServer():
    global _xmlrpc_api_server
    if _xmlrpc_api_server is not None:
        _xmlrpc_api_server.stop_server()
        devlog("called stop on xmlrpc server")
        _xmlrpc_api_server.join()
        devlog("xmlrpc thread joined")


def _setUpAPIServer(hostname=None, port=None):
    global _xmlrpc_api_server
    global api_conn_info
    if _xmlrpc_api_server is None:
        #TODO: some way to get defaults.. from config?
        if str(hostname) == "None":
            hostname = "localhost"
        if str(port) == "None":
            port = 9876

        if CONF.getApiConInfo() is None:
            CONF.setApiConInfo(hostname, port)
        devlog("starting XMLRPCServer with api_conn_info = %s" % str(CONF.getApiConInfo()))

        while True:

            try:
                _xmlrpc_api_server = model.common.XMLRPCServer(CONF.getApiConInfo())
                # Registers the XML-RPC introspection functions system.listMethods, system.methodHelp and system.methodSignature.
                _xmlrpc_api_server.register_introspection_functions()

                # register a function to nicely stop server
                _xmlrpc_api_server.register_function(_xmlrpc_api_server.stop_server)

                # register all the api functions to be exposed by the server
                _xmlrpc_api_server.register_function(createAndAddHost)
                _xmlrpc_api_server.register_function(createAndAddInterface)
                _xmlrpc_api_server.register_function(createAndAddServiceToInterface)
                _xmlrpc_api_server.register_function(createAndAddNoteToService)
                _xmlrpc_api_server.register_function(createAndAddNoteToHost)
                _xmlrpc_api_server.register_function(createAndAddNoteToNote)
                _xmlrpc_api_server.register_function(createAndAddVulnWebToService)
                _xmlrpc_api_server.register_function(createAndAddVulnToService)
                _xmlrpc_api_server.register_function(createAndAddVulnToHost)
                _xmlrpc_api_server.register_function(addHost)
                _xmlrpc_api_server.register_function(addInterface)
                _xmlrpc_api_server.register_function(addServiceToInterface)
                _xmlrpc_api_server.register_function(newHost)
                _xmlrpc_api_server.register_function(newInterface)
                _xmlrpc_api_server.register_function(newService)
                _xmlrpc_api_server.register_function(devlog)

                #TODO: check if all necessary APIs are registered here!!

                getLogger().info(
                    "XMLRPC API server configured on %s" % str(
                        CONF.getApiConInfo()))
                break
            except socket.error as exception:
                if exception.errno == 98:
                    # Port already in use
                    # Let's try the next one
                    port += 1
                    if port > 65535:
                        raise Exception("No ports available!")
                    CONF.setApiConInfo(hostname, port)
                    CONF.saveConfig()
                else:
                    raise exception
            except Exception as e:
                msg = "There was an error creating the XMLRPC API Server:\n%s" % str(e)
                log(msg)
                devlog("[ERROR] - %s" % msg)


#-------------------------------------------------------------------------------
# APIs to create and add elements to model
#-------------------------------------------------------------------------------

#TODO: create a decorator to find the caller of an api to try to determine which
# plugin created the object


def createAndAddHost(name, os="Unknown"):
    host = newHost(name, os)
    if addHost(host):
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
                             ipv4_dns,ipv6_address,ipv6_prefix,ipv6_gateway,ipv6_dns,
                             network_segment, hostname_resolution, parent_id=host_id)
    if addInterface(host_id, interface):
        return interface.getID()
    return None

def createAndAddServiceToInterface(host_id, interface_id, name, protocol = "tcp?",
                ports = [], status = "running", version = "unknown", description = ""):
    service = newService(name, protocol, ports, status, version, description, parent_id=interface_id)
    if addServiceToInterface(host_id, interface_id, service):
        return service.getID()
    return None

# Vulnerability

def createAndAddVulnToHost(host_id, name, desc, ref, severity, resolution):
    vuln = newVuln(name, desc, ref, severity, resolution, parent_id=host_id)
    if addVulnToHost(host_id, vuln):
        return vuln.getID()
    return None

def createAndAddVulnToInterface(host_id, interface_id, name, desc, ref, severity, resolution):
    vuln = newVuln(name, desc, ref, severity, resolution, parent_id=interface_id)
    if addVulnToInterface(host_id, interface_id, vuln):
        return vuln.getID()
    return None

def createAndAddVulnToService(host_id, service_id, name, desc, ref, severity, resolution):
    #we should give the interface_id or de application_id too? I think we should...
    vuln = newVuln(name, desc, ref, severity, resolution, parent_id=service_id)
    if addVulnToService(host_id, service_id, vuln):
        return vuln.getID()
    return None

#WebVuln

def createAndAddVulnWebToService(host_id, service_id, name, desc, ref, severity, resolution, website, path, request, response,
                method,pname, params,query,category):
    #we should give the interface_id or de application_id too? I think we should...
    vuln = newVulnWeb(name, desc, ref, severity, resolution, website, path, request, response,
                method,pname, params, query, category, parent_id=service_id)
    if addVulnWebToService(host_id, service_id, vuln):
        return vuln.getID()
    return None

# Note

def createAndAddNoteToHost(host_id, name, text):
    note = newNote(name, text, parent_id=host_id)
    if addNoteToHost(host_id, note):
        return note.getID()
    return None

def createAndAddNoteToInterface(host_id, interface_id, name, text):
    note = newNote(name, text, parent_id=interface_id)
    if addNoteToInterface(host_id, interface_id, note):
        return note.getID()
    return None

def createAndAddNoteToService(host_id, service_id, name, text):
    note = newNote(name, text, parent_id=service_id)
    if addNoteToService(host_id, service_id, note):
        return note.getID()
    return None

def createAndAddNoteToNote(host_id, service_id, note_id, name, text):
    note = newNote(name, text, parent_id=note_id)
    if addNoteToNote(host_id, service_id, note_id, note):
        return note.getID()
    return None

def createAndAddCredToService(host_id, service_id, username, password):
    cred = newCred(username, password, parent_id=service_id)
    if addCredToService(host_id, service_id, cred):
        return cred.getID()
    return None

#-------------------------------------------------------------------------------
# APIs to add already created objets to the model
#-------------------------------------------------------------------------------

#TODO: add class check to object passed to be sure we are adding the right thing to the model

def addHost(host):
    if host is not None:
        __model_controller.addHostASYNC(host)
        return True
    return False

def addInterface(host_id, interface):
    if interface is not None:
        __model_controller.addInterfaceASYNC(host_id, interface)
        return True
    return False


def addServiceToInterface(host_id, interface_id, service):
    if service is not None:
        __model_controller.addServiceToInterfaceASYNC(host_id, interface_id, service)
        return True
    return False

# Vulnerability

def addVulnToHost(host_id, vuln):
    if vuln is not None:
        __model_controller.addVulnToHostASYNC(host_id, vuln)
        return True
    return False

def addVulnToInterface(host_id, interface_id, vuln):
    if vuln is not None:
        __model_controller.addVulnToInterfaceASYNC(host_id, interface_id, vuln)
        return True
    return False

def addVulnToService(host_id, service_id, vuln):
    if vuln is not None:
        __model_controller.addVulnToServiceASYNC(host_id, service_id, vuln)
        return True
    return False

#VulnWeb
def addVulnWebToService(host_id, service_id, vuln):
    if vuln is not None:
        __model_controller.addVulnWebToServiceASYNC(host_id, service_id, vuln)
        return True
    return False

# Notes

def addNoteToHost(host_id, note):
    if note is not None:
        __model_controller.addNoteToHostASYNC(host_id, note)
        return True
    return False

def addNoteToInterface(host_id, interface_id, note):
    if note is not None:
        __model_controller.addNoteToInterfaceASYNC(host_id, interface_id, note)
        return True
    return False

def addNoteToService(host_id, service_id, note):
    if note is not None:
        __model_controller.addNoteToServiceASYNC(host_id, service_id, note)
        return True
    return False

def addNoteToNote(host_id, service_id, note_id, note):
    if note is not None:
        __model_controller.addNoteToNoteASYNC(host_id, service_id, note_id, note)
        return True
    return False

def addCredToService(host_id, service_id, cred):
    if cred is not None:
        __model_controller.addCredToServiceASYNC(host_id, service_id, cred)
        return True
    return False

#-------------------------------------------------------------------------------
# APIs to delete elements to model
#-------------------------------------------------------------------------------
#TODO: delete funcitons are still missing
def delHost(hostname):
    __model_controller.delHostASYNC(hostname)
    return True


def delInterface(hostname,intname):
    __model_controller.delInterfaceASYNC(hostname,intname)
    return True

def delServiceFromHost(hostname, service):
    __model_controller.delServiceFromHostASYNC(hostname, service)
    return True

def delServiceFromInterface(hostname, intname, service, remote = True):
    __model_controller.delServiceFromInterfaceASYNC(hostname,intname,service)
    return True


# Vulnerability
#-------------------------------------------------------------------------------
def delVulnFromInterface(vuln, hostname, intname):
    __model_controller.delVulnFromInterfaceASYNC(hostname,intname, vuln)
    return True
#-------------------------------------------------------------------------------
def delVulnFromHost(vuln, hostname):
    __model_controller.delVulnFromHostASYNC(hostname,vuln)
    return True

#-------------------------------------------------------------------------------
def delVulnFromService(vuln, hostname, srvname):
    __model_controller.delVulnFromServiceASYNC(hostname,srvname, vuln)
    return True

# Notes
#-------------------------------------------------------------------------------
def delNoteFromInterface(note, hostname, intname):
    __model_controller.delNoteFromInterfaceASYNC(hostname,intname, note)
    return True
#-------------------------------------------------------------------------------
def delNoteFromHost(note, hostname):
    __model_controller.delNoteFromHostASYNC(hostname, note)
    return True

#-------------------------------------------------------------------------------
def delNoteFromService(note, hostname, srvname):
    __model_controller.delNoteFromServiceASYNC(hostname,srvname, note)
    return True

#-------------------------------------------------------------------------------
def delCredFromService(cred, hostname, srvname):
    __model_controller.delCredFromServiceASYNC(hostname,srvname, cred)
    return True

#-------------------------------------------------------------------------------
# CREATION APIS
#-------------------------------------------------------------------------------

def newHost(name, os = "Unknown"):
    """
    It creates and returns a Host object.
    The object created is not added to the model.
    """
    return __model_controller.newHost(name, os)

def newInterface(name = "", mac = "00:00:00:00:00:00",
                 ipv4_address = "0.0.0.0", ipv4_mask = "0.0.0.0",
                 ipv4_gateway = "0.0.0.0", ipv4_dns = [],
                 ipv6_address = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_prefix = "00",
                 ipv6_gateway = "0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns = [],
                 network_segment = "", hostname_resolution = [], parent_id=None):
    """
    It creates and returns an Interface object.
    The created object is not added to the model.
    """
    return __model_controller.newInterface(
        name, mac, ipv4_address, ipv4_mask, ipv4_gateway, ipv4_dns,
        ipv6_address, ipv6_prefix, ipv6_gateway, ipv6_dns, network_segment,
        hostname_resolution, parent_id)

def newService(name, protocol = "tcp?", ports = [], status = "running",
               version = "unknown", description = "", parent_id=None):
    """
    It creates and returns a Service object.
    The created object is not added to the model.
    """
    return __model_controller.newService(
        name, protocol, ports, status, version, description, parent_id)


def newVuln(name, desc="", ref=None, severity="", resolution="",
            confirmed=False, parent_id=None):
    """
    It creates and returns a Vulnerability object.
    The created object is not added to the model.
    """
    return __model_controller.newVuln(
        name, desc, ref, severity, resolution, confirmed, parent_id)


def newVulnWeb(name, desc="", ref=None, severity="", resolution="", website="",
               path="", request="", response="", method="", pname="",
               params="", query="", category="", confirmed=False,
               parent_id=None):
    """
    It creates and returns a Vulnerability object.
    The created object is not added to the model.
    """
    return __model_controller.newVulnWeb(
        name, desc, ref, severity, resolution, website, path, request,
        response, method, pname, params, query, category, confirmed,
        parent_id)


def newNote(name, text, parent_id=None):
    """
    It creates and returns a Note object.
    The created object is not added to the model.
    """
    return __model_controller.newNote(name, text, parent_id)


def newCred(username, password, parent_id=None):
    """
    It creates and returns a Cred object.
    The created object is not added to the model.
    """
    return __model_controller.newCred(username, password, parent_id)

#-------------------------------------------------------------------------------

#getConflicts: get the current conflicts
def getConflicts():
    return __model_controller.getConflicts()

#-------------------------------------------------------------------------------
# EVIDENCE
#-------------------------------------------------------------------------------
#TODO: refactor!! acomodar estos metodos para que no accedan a cosas directas del model_controller
def addEvidence(file_path):
    """
    Copy evidence file to the repository
    """
    filename=os.path.basename(file_path)
    ###: Ver de sacar ese nombre evidences del config

    dpath="%s/evidences/" % (__model_controller._persistence_dir)
    dpathfilename="%s%s" % (dpath,filename)

    #devlog("[addEvidence] File added ("+file_path+") destination path ("+dpathfilename+")")

    if os.path.isfile(dpathfilename):
        devlog("[addEvidence] - File evidence (" + dpathfilename +") exists abort adding")
    else:
        if not os.path.isdir(dpath):
            os.mkdir(dpath)

        shutil.copyfile(file_path,dpathfilename)
        if os.path.isfile(dpathfilename):
            #XXX: la idea es no acceder directamente a cosas privadas del model controller como esto de _check_evidences
            __model_controller._check_evidences.append(dpathfilename)
            return dpathfilename

    return False

def checkEvidence(file_path):
    """
    Copy evidence file to the repository
    """
    if not os.path.isfile(file_path):
        devlog("[addEvidence] - File evidence (" + dpathfilename +") doesnt exists abort adding")
    else:
        __model_controller._check_evidences.append(file_path)
        return True

    return False

def cleanEvidence():
    """
    Copy evidence file to the repository
    """
    check_evidences=__model_controller._check_evidences
    #devlog("[cleanEvidence] check_evidence values=" + str(check_evidences))

    evidence_path="%s/evidences/" % (__model_controller._persistence_dir)
    for root, dirs, files in os.walk(evidence_path):
        for filename in files:
            if os.path.splitext(filename)[1].lower() == ".png":
                f=os.path.join(root, filename)
                if f in check_evidences:
                    devlog("[cleanEvidence] - The following file is in the evidence xml" + os.path.join(root, filename))
                else:
                    delEvidence(f)
            #__model_controller._check_evidences=[]
        return True

    return False

def delEvidence(file_path):
    """
    Add file_path to the queue to be delete from the svn and filesystem
    """
    if os.path.isfile(file_path):
        devlog("[addEvidence] - Adding file (" + file_path +") to the delete queue")
        __model_controller._deleted_evidences.append(file_path)
        return True
    else:
        devlog("[addEvidence] - File evidence (" + file_path +") doesnt exist abort deleting")

    return False

#-------------------------------------------------------------------------------
# MISC APIS
#-------------------------------------------------------------------------------
def log(msg ,level = "INFO"):
    """
    This api will log the text in the GUI console without the level
    it will also log to a file with the corresponding level
    if logger was configured that way
    """
    levels = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
        "NOTSET": logging.NOTSET
    }
    level = levels.get(level, logging.NOTSET)
    getLogger().log(level, msg)

def devlog(msg):
    """
    If DEBUG is set it will print information directly to stdout
    """
    getLogger().debug(msg)

def showDialog(msg, level="Information"):
    return model.log.getNotifier().showDialog(msg, level)

def showPopup(msg, level="Information"):
    return model.log.getNotifier().showPopup(msg, level)


# Plugin status

def pluginStart(name):
    __model_controller.addPluginStart(name)

def pluginEnd(name):
    __model_controller.addPluginEnd(name)

#-------------------------------------------------------------------------------
def getLoggedUser():
    """
    Returns the currently logged username
    """
    global __current_logged_user
    return __current_logged_user
#-------------------------------------------------------------------------------

#TODO: implement!!!!!
def getLocalDefaultGateway():
    return gateway()

def getActiveWorkspace():
    return __workspace_manager.getActiveWorkspace()
