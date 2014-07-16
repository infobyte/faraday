'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import time
import threading
import Queue
import traceback
import datetime
import model.common # this is to make sure the factory is created
import model.hosts

from config.configuration import getInstanceConfiguration
from model.common import TreeWordsTries
from model.container import ModelObjectContainer
from utils.logs import getLogger
import model.api as api
#import model.guiapi as guiapi
from model.guiapi import notification_center as notifier
from gui.customevents import *

from model.workspace import WorkspaceSyncronizer
from utils.decorators import lockModel
from utils.common import get_hash

from model.conflict import Conflict, ConflictUpdate


#XXX: consider re-writing this module! There's alot of repeated code
# and things are really messy

CONF = getInstanceConfiguration()


class modelactions:
    ADDHOST = 2000
    DELHOST = 2001
    ADDINTERFACE = 2002
    DELINTERFACE = 2003
    ADDSERVICEINT = 2004
    ADDSERVICEAPP = 2005
    DELSERVICEINT = 2006
    DELSERVICEAPP = 2007
    ADDAPPLICATION = 2009
    ADDCATEGORY = 2011
    ADDVULNINT = 2013
    DELVULNINT = 2014
    ADDVULNAPP = 2015
    DELVULNAPP = 2016
    ADDVULNHOST = 2017
    DELVULNHOST = 2018
    ADDVULNSRV = 2019
    DELVULNSRV = 2020
    ADDNOTEINT = 2021
    DELNOTEINT = 2022
    ADDNOTEAPP = 2023
    DELNOTEAPP = 2024
    ADDNOTEHOST = 2025
    DELNOTEHOST = 2026
    ADDNOTESRV = 2027
    DELNOTESRV = 2028
    RENAMEROOT = 2029
    ADDNOTEVULN = 2030
    DELNOTEVULN = 2031
    EDITHOST = 2032
    EDITINTERFACE = 2033
    EDITAPPLICATION = 2034
    EDITSERVICE = 2035
    ADDCREDSRV = 2036
    DELCREDSRV = 2037
    ADDVULNWEBSRV = 2038
    DELVULNWEBSRV = 2039
    ADDNOTENOTE = 2040
    DELNOTENOTE = 2041
    EDITNOTE = 2042
    EDITVULN = 2043
    ADDNOTE = 2044
    DELNOTE = 2045
    ADDVULN = 2046
    DELVULN = 2047
    EDITCRED = 2048
    ADDCRED = 2049
    DELCRED = 2050

    __descriptions = {
        ADDHOST: "ADDHOST",
        DELHOST: "DELHOST",
        ADDINTERFACE: "ADDINTERFACE",
        DELINTERFACE: "DELINTERFACE",
        ADDSERVICEINT: "ADDSERVICEINT",
        ADDSERVICEAPP: "ADDSERVICEAPP",
        DELSERVICEINT: "DELSERVICEINT",
        DELSERVICEAPP: "DELSERVICEAPP",
        ADDAPPLICATION: "ADDAPPLICATION",
        ADDCATEGORY: "ADDCATEGORY",
        ADDVULNINT: "ADDVULNINT",
        DELVULNINT: "DELVULNINT",
        ADDVULNAPP: "ADDVULNAPP",
        DELVULNAPP: "DELVULNAPP",
        ADDVULNHOST: "ADDVULNHOST",
        DELVULNHOST: "DELVULNHOST",
        ADDVULNSRV: "ADDVULNSRV",
        DELVULNSRV: "DELVULNSRV",
        ADDNOTEVULN: "ADDNOTEVULN",
        DELNOTEVULN: "DELNOTEVULN",
        ADDNOTENOTE: "ADDNOTENOTE",
        DELNOTENOTE: "DELNOTENOTE",
        EDITHOST: "EDITHOST",
        EDITINTERFACE: "EDITINTERFACE",
        EDITAPPLICATION: "EDITAPPLICATION",
        EDITSERVICE: "EDITAPPLICATION",
        ADDCREDSRV: "ADDCREDSRV",
        DELCREDSRV: "DELCREDSRV",
        ADDVULNWEBSRV: "ADDVULNSWEBRV",
        DELVULNWEBSRV: "DELVULNWEBSRV",
        EDITNOTE: "EDITNOTE",
        EDITVULN: "EDITVULN",
        EDITCRED: "EDITCRED",
        ADDNOTE: "ADDNOTE",
        DELNOTE: "DELNOTE",
        ADDVULN: "ADDVULN",
        DELVULN: "DELVULN",
        ADDCRED: "ADDCRED",
        DELCRED: "DELCRED"
    }

    @staticmethod
    def getDescription(action):
        return modelactions.__descriptions.get(action, "")


class ModelController(threading.Thread):

    def __init__(self, security_manager, mappers_manager):
        threading.Thread.__init__(self)

        self.__sec = security_manager
        self.mappers_manager = mappers_manager

        # set as daemon
        self.setDaemon(True)

        #TODO: think of a good way to handle cross reference between hosts and
        #categories
        self._categories = {}
        self._categories[CONF.getDefaultCategory()] = []

        # dictionary with host ids as key
        self._hosts = None

        # flag to stop daemon thread
        self._stop = False
        # locks needed to make model thread-safe
        self._hosts_lock = threading.RLock()

        #TODO: check if it is better using collections.deque
        # a performance analysis should be done
        # http://docs.python.org/library/collections.html#collections.deque

        # the actions queue
        self._pending_actions = Queue.Queue()

        # a reference to the ModelObjectFactory
        self._object_factory = model.common.factory
        self._registerObjectTypes()

        # sync api request flag. This flag is used to let the model know
        # there's some other object trying to use a sync api, and it should
        # give priority to that and stop processing the queue
        self._sync_api_request = False

        # This flag & lock are used when the complete model is being persisted
        self._saving_model_flag = False
        self._saving_model_lock = threading.RLock()

        self._actionDispatcher = None
        self._setupActionDispatcher()

        self._workspace = None

        self.objects_with_updates = []

        #used to highligthing
        self.treeWordsTries = TreeWordsTries()

    def __getattr__(self, name):
        getLogger(self).debug("ModelObject attribute to refactor: %s" % name)

    def _getValueByID(self, attrName, ID):
        """
        attribute passed as a parameter MUST BE a dictionary indexed with a
        string ID
        if id is found as a part of a key it returns the object
        it returns None otherwise
        """
        if ID:
            hash_id = get_hash([ID])
            ref = self.__getattribute__(attrName)
            # we are assuming the value is unique inside the object ID's
            #for key in ref:
            for key in ref.keys():
                #XXX: this way of checking the ids doesn't allow us to use a real hash as key
                # because we are checking if "id" is part of the key... not a good way  of
                # dealing with this...
                if hash_id == key or ID == key:
                    return ref[key]
            # if id (hash) was not found then we try with element names
            for element in ref.itervalues():
                #if id in element.name:
                if ID == element.name:
                    return element
        return None

    def _addValue(self, attrName, newValue, setparent=False, update=False):
        # attribute passed as a parameter MUST BE  the name
        # of an internal attribute which is a dictionary indexed
        # with a string ID
        valID = newValue.getID()
        ref = self.__getattribute__(attrName)
        #if valID not in ref or update:
        if valID not in ref or update:
            #TODO: Is this necesary?
            if setparent:
                newValue.setParent(self)
            ref[valID] = newValue
            return True
            #return not update
        return False

    def __acquire_host_lock(self):
        self._saving_model_lock.acquire()
        self._saving_model_lock.release()
        self._hosts_lock.acquire()

    def __release_host_lock(self):
        try:
            self._hosts_lock.release()
        except RuntimeError:
            pass

    def _registerObjectTypes(self):
        """
        Registers in the factory all object types that can be created
        """
        # This could be done in hosts module, but it seems easier to maintain
        # if we have all in one place inside the controller
        self._object_factory.register(model.hosts.Host)
        self._object_factory.register(model.hosts.Interface)
        self._object_factory.register(model.hosts.Service)
        self._object_factory.register(model.hosts.HostApplication)
        self._object_factory.register(model.common.ModelObjectVuln)
        self._object_factory.register(model.common.ModelObjectVulnWeb)
        self._object_factory.register(model.common.ModelObjectNote)
        self._object_factory.register(model.common.ModelObjectCred)

    def _setupActionDispatcher(self):
        self._actionDispatcher = {
            modelactions.ADDHOST: self.__add,
            modelactions.DELHOST: self.__del,
            modelactions.EDITHOST: self.__edit,
            modelactions.ADDINTERFACE: self.__add,
            modelactions.DELINTERFACE: self.__del,
            modelactions.EDITINTERFACE: self.__edit,
            modelactions.ADDSERVICEINT: self.__add,
            modelactions.DELSERVICEINT: self.__del,
            modelactions.EDITSERVICE: self.__edit,
            modelactions.EDITAPPLICATION: self.__editApplication,
            #Vulnerability
            modelactions.ADDVULNINT: self.__add,
            modelactions.DELVULNINT: self._delVulnerabilityFromInterface,
            modelactions.ADDVULNHOST: self.__add,
            modelactions.DELVULNHOST: self.__del,
            modelactions.ADDVULNSRV: self.__add,
            modelactions.DELVULNSRV: self.__del,
            modelactions.ADDVULN: self.__addVulnToModelObject,
            modelactions.DELVULN: self.__del,
            modelactions.ADDVULNWEBSRV: self.__addVulnerabilityToService,
            modelactions.EDITVULN: self.__edit,
            #Note
            modelactions.ADDNOTEINT: self.__add,
            modelactions.DELNOTEINT: self.__del,
            modelactions.ADDNOTEHOST: self.__add,
            modelactions.DELNOTEHOST: self.__del,
            modelactions.ADDNOTESRV: self.__add,
            modelactions.DELNOTESRV: self.__del,
            modelactions.ADDNOTEVULN: self.__add,
            modelactions.ADDNOTE: self.__add,
            modelactions.DELNOTE: self.__del,
            modelactions.ADDCREDSRV: self.__add,
            modelactions.DELCREDSRV: self.__del,
            modelactions.ADDNOTENOTE: self.__add,
            modelactions.EDITNOTE: self.__edit,
            modelactions.EDITCRED: self.__edit,
            modelactions.ADDCRED: self.__add,
            modelactions.DELCRED: self.__del
        }

    def run(self):
        return self._main()

    def stop(self):
        """
        Sets the flag to stop daemon
        """
        self._stop = True

    def _dispatchActionWithLock(self, action_callback, *args):
        res = False
        self.__acquire_host_lock()
        try:
            res = action_callback(*args)
        except Exception:
            api.log("An exception occurred while dispatching an action (%r(%r)\n%s" %
                   (action_callback, args, traceback.format_exc()), "ERROR")
        finally:
            self.__release_host_lock()
        return res

    def _processAction(self, action, parameters, sync=False):
        """
        decodes and performs the action given
        It works kind of a dispatcher
        """
        if sync:
            self._sync_api_request = True

        api.devlog("_processAction - %s - parameters = %s" %
                  (action, str(parameters)))

        action_callback = self._actionDispatcher[action]
        res = self._dispatchActionWithLock(action_callback, *parameters)

        # finally we notify the widgets about this change
        #if res: # notify only if action was done successfuly
            #self._notifyModelUpdated(*parameters)
        #else:
        if not res:
            api.devlog("Action code %d failed. Parameters = %s" %
                      (action, str(parameters)))
        if sync:
            self._sync_api_request = False

    def getConflicts(self):
        conflicts = []
        for obj in self.objects_with_updates:
            conflicts += obj.getUpdates()
        return conflicts

    def resolveConflicts(self):
        notifier.conflictResolution(self.getConflicts())

    def resolveConflict(self, conflict, kwargs):
        if conflict.resolve(kwargs):
            if conflict.getModelObjectType() == "Interface":
                ipv4 = kwargs['ipv4']
                ipv6 = kwargs['ipv6']
                hostnames = kwargs['hostnames']

                if not ipv4['address'] in ["0.0.0.0", None]:
                    self.treeWordsTries.removeWord(ipv4['address'])
                    self.treeWordsTries.addWord(ipv4['address'])

                if not ipv6['address'] in ["0000:0000:0000:0000:0000:0000:0000:0000", None]:
                    self.treeWordsTries.removeWord(ipv6['address'])
                    self.treeWordsTries.addWord(ipv6['address'])

                for h in hostnames:
                    if h is not None:
                        self.treeWordsTries.removeWord(h)
                        self.treeWordsTries.addWord(h)

            notifier.conflictUpdate(-1)
            notifier.editHost(conflict.getFirstObject().getHost())
            #self._notifyModelUpdated()

    def removeConflictsByObject(self, obj):
        if obj in self.objects_with_updates:
            self.objects_with_updates.remove(obj)
        notifier.conflictUpdate(-len(obj.getUpdates()))

    def setSavingModel(self, value):
        api.devlog("setSavingModel: %s" % value)
        self._saving_model_flag = value
        if value:
            self._saving_model_lock.acquire()
        else:
            try:
                self._saving_model_lock.release()
            except RuntimeError:
                pass

    def _main(self):
        """
        The main method for the thread.
        The controller will be constantly checking a queue
        to see if new actions were added.
        This will make host addition and removal "thread-safe" and will
        avoid locking components that need to interact with the model
        """
        while True:
            # check if thread must finish
            if self._stop:
                return
            # first we check if there is a sync api request
            # or if the model is being saved/sync'ed
            # or if we have pending duplicated hosts that need to be
            # merged by the user
            if not self._sync_api_request and not self._saving_model_flag:

                self.processAction()
            else:
                # there is some object requesting for a sync api so we
                # sleep the thread execution for a moment to let others work
                # XXX: check if this time is not too much...
                time.sleep(0.01)

    def processAllPendingActions(self):
        [self.processAction() for i in range(self._pending_actions.qsize())]

    def processAction(self):
        # check the queue for new actions
        # if there is no new action it will block until timeout is reached
        try:
            # get new action or timeout (in secs)
            #TODO: timeout should be set through config
            current_action = self._pending_actions.get(timeout=2)
            action = current_action[0]
            parameters = current_action[1:]
            # dispatch the action
            self._processAction(action, parameters)
        except Queue.Empty:
            # if timeout was reached, just let the daemon run again
            # this is done just to be able to test the stop flag
            # because if we don't do it, the daemon will be blocked forever
            pass
        except Exception:
            getLogger(self).devlog("something strange happened... unhandled exception?")
            getLogger(self).devlog(traceback.format_exc())

    def sync_lock(self):
        self._sync_api_request = True
        self.__acquire_host_lock()

    def sync_unlock(self):
        self._sync_api_request = False
        self.__release_host_lock()

    # TODO: >>> APIs <<< we have to know which plugin called the apis to store
    # in the history

    def __addPendingAction(self, *args):
        """
        Adds a new pending action to the queue
        Action is build with generic args tuple.
        The caller of this function has to build the action in the right
        way since no checks are preformed over args
        """
        new_action = args
        self._pending_actions.put(new_action)


    def addUpdate(self, old_object, new_object):
        # Returns True if the update was resolved without user interaction
        res = True
        try:
            mergeAction = old_object.addUpdate(new_object)
            if mergeAction:
                if old_object not in self.objects_with_updates:
                    self.objects_with_updates.append(old_object)
                notifier.conflictUpdate(1)
                res = False
        except:
            res = False
            api.devlog("(%s).addUpdate(%s, %s) - failed" %
                      (self, old_object, new_object))
        return res

    def addHostASYNC(self, host, category=None, update=False, old_hostname=None):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        new host must be added to the model
        """
        self.__addPendingAction(modelactions.ADDHOST, host, category, update, old_hostname)

    def addHostSYNC(self, host, category=None, update=False, old_hostname=None):
        """
        SYNC API
        Adds a host directly to the model
        """
        self._processAction(modelactions.ADDHOST, [host, None], sync=True)

    def __add(self,  obj, parent_id=None, *args):
        dataMapper = self.mappers_manager.getMapper(obj)
        object_parent = self.mappers_manager.findObject(parent_id)
        object_parent.addChild(obj.getID(), obj)
        dataMapper.saveObject(obj) 
        self.treeWordsTries.addWord(obj.getName())
        notifier.addHost(obj)

    def __edit(self, objId, *args, **kwargs):
        obj = self.mappers_manager.findObject(objId)
        obj.updateAttributes(*args, **kwargs)
        self.mappers_manager.saveObject(obj) 
        # self.treeWordsTries.addWord(obj.getName())
        # notifier.addHost(obj)

    def __del(self,  objId, *args):
        dataMapper = self.mappers_manager.getMapper(objId) 
        obj = self.mappers_manager.findObject(objId)
        obj_parent = obj.getParent() 
        if obj_parent:
            obj_parent.deleteChild(objId) 

        self.treeWordsTries.removeWord(obj.getName())

        dataMapper.delObject(objId) 
        notifier.delHost(objId)


    def delHostASYNC(self, hostId):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular host must be removed from the model
        """
        self.__addPendingAction(modelactions.DELHOST, hostId)

    def delHostSYNC(self, host):
        """
        SYNC API
        Deletes a host from model
        """
        self._processAction(modelactions.DELHOST, [host.getID()], sync=True)

    def __clearHost(self, host):
        self.__clearModelObject(host)
        self.__delInterfaces(host)

    def __clearInterface(self, interface):
        self.__clearModelObject(interface)
        self.__delServices(interface)

    def __clearApplication(self, application):
        self.__clearModelObject(application)
        self.__delServices(application)

    def __clearService(self, service):
        self.__clearModelObject(service)

    def __clearNote(self, note):
        self.__clearModelObject(note)

    def __clearVuln(self, vuln):
        self.__clearModelObject(vuln)

    def __clearCred(self, cred):
        self.__clearModelObject(cred)

    def __clearModelObject(self, modelObj):
        self.removeConflictsByObject(modelObj)
        self.__delNotes(modelObj)
        self.__delVulns(modelObj)
        self.__delCreds(modelObj)

    def __delNotes(self, modelObj):
        for note in list(modelObj.getNotes()):
            self.__clearNote(note)
            modelObj.delNote(note.getID())

    def __delVulns(self, modelObj):
        for vuln in list(modelObj.getVulns()):
            self.__clearVuln(vuln)
            modelObj.delVuln(vuln.getID())

    def __delCreds(self, modelObj):
        for cred in list(modelObj.getCreds()):
            self.__clearCred(cred)
            modelObj.delCred(cred.getID())

    def __delInterfaces(self, modelObj):
        for interface in list(modelObj.getAllInterfaces()):
            self.__clearInterface(interface)
            modelObj.delInterface(interface.getID())

    def __delServices(self, modelObj):
        for service in list(modelObj.getAllServices()):
            self.__clearService(service)
            modelObj.delService(service.getID())

    def editHostSYNC(self, host, name, description, os, owned):
        """
        SYNC API
        Modifies a host from model
        """
        self._processAction(modelactions.EDITHOST, [host, name, description, os, owned], sync=True)

    def addInterfaceASYNC(self, hostid, interface, update=False):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        new interface must be added to a specific host
        """
        self.__addPendingAction(modelactions.ADDINTERFACE, interface, hostid)

    def addInterfaceSYNC(self, hostId, interface, update=False):
        """
        SYNC API
        Adds interface directly to the model
        """
        self._processAction(modelactions.ADDINTERFACE, [interface, hostId], sync=True)

    def delInterfaceASYNC(self, hostId, interfaceId):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular host must be removed from the model
        """
        self.__addPendingAction(modelactions.DELINTERFACE, interfaceId, hostId)

    def delInterfaceSYNC(self, host, interface_id, *args):
        """
        SYNC API
        Deletes an interface from model
        """
        self._processAction(modelactions.DELINTERFACE, [interface_id], sync=True)

    def editInterfaceSYNC(self, interface, name, description, hostnames,
                          mac, ipv4, ipv6, network_segment,
                          amount_ports_opened, amount_ports_closed,
                          amount_ports_filtered, owned):
        """
        SYNC API
        Modifies an interface from model
        """
        self._processAction(modelactions.EDITINTERFACE,
                            [interface, name, description, hostnames,
                             mac, ipv4, ipv6, network_segment,
                             amount_ports_opened, amount_ports_closed,
                             amount_ports_filtered, owned], sync=True)

    def addServiceToInterfaceASYNC(self, host, interfaceId, newService):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        new services must be added to a specific host in a specific interface
        """
        self.__addPendingAction(modelactions.ADDSERVICEINT, newService, interfaceId)

    def addServiceToInterfaceSYNC(self, host_id, interface_id, newService):
        """
        SYNC API
        Adds a service to a specific host in a specific interface
        directly to the model
        """
        self._processAction(modelactions.ADDSERVICEINT, [newService, interface_id], sync=True)

    def delServiceFromInterfaceASYNC(self, host, interfaceId, serviceId):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular service in a host and interface must be removed from the
        model Interface parameter can be "ALL"
        """
        self.__addPendingAction(modelactions.DELSERVICEINT, serviceId, interfaceId)

    def delServiceFromInterfaceSYNC(self, host, interfaceId, serviceId):
        """
        SYNC API
        Delete a service in a host and interface from the model
        """
        self._processAction(modelactions.DELSERVICEINT, [serviceId], sync=True)

    def delServiceFromApplicationASYNC(self, host, appname, service):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular service in a host and interface must be removed from the model
        appname parameter can be "ALL"
        """
        self.__addPendingAction(modelactions.DELSERVICEAPP, host, appname, service)

    def delServiceFromApplicationSYNC(self, host, appname, service):
        """
        SYNC API
        Delete a service in a host and application from the model
        """
        self._processAction(modelactions.DELSERVICEAPP, [host, appname, service], sync=True)

    def editServiceSYNC(self, service, name, description, protocol, ports, status, version, owned):
        """
        SYNC API
        Modifies a host from model
        """
        self._processAction(modelactions.EDITSERVICE, [service, name, description, protocol, ports, status, version, owned], sync=True)

    def editServiceASYNC(self, service, name, description, protocol, ports, status, version, owned):
        """
        ASYNC API
        Modifies a service from model
        """
        self.__addPendingAction(modelactions.EDITSERVICE, service, name, description, protocol, ports, status, version, owned)

    def __editService(self, service, name=None, description=None,
                      protocol=None, ports=None, status=None,
                      version=None, owned=None):
        res = False
        if service is not None:
            service.updateAttributes(name, description, protocol, ports, status, version, owned)
            notifier.editHost(service.getHost())
            res = True
        return res

    def addVulnToInterfaceASYNC(self, host, intId, newVuln):
        self.__addPendingAction(modelactions.ADDVULNINT, newVuln, intId)

    def addVulnToInterfaceSYNC(self, host, intId, newVuln):
        self._processAction(modelactions.ADDVULNINT, [newVuln, intId], sync=True)

    def addVulnToApplicationASYNC(self, host, appname, newVuln):
        self.__addPendingAction(modelactions.ADDVULNAPP, host, appname, newVuln)

    def addVulnToApplicationSYNC(self, host, appname, newVuln):
        self._processAction(modelactions.ADDVULNAPP, [host, appname, newVuln], sync=True)

    def addVulnToHostASYNC(self, hostId, newVuln):
        self.__addPendingAction(modelactions.ADDVULNHOST, newVuln, hostId)

    def addVulnToHostSYNC(self, hostId, newVuln):
        self._processAction(modelactions.ADDVULNHOST, [newVuln, hostId], sync=True)

    def addVulnToServiceASYNC(self, host, srvId, newVuln):
        self.__addPendingAction(modelactions.ADDVULNSRV, newVuln, srvId)

    def addVulnToServiceSYNC(self, host, srvId, newVuln):
        self._processAction(modelactions.ADDVULNSRV, [newVuln, srvId], sync=True)

    def addVulnSYNC(self, model_object, newVuln):
        self._processAction(modelactions.ADDVULN, [model_object, newVuln], sync=True)

    def addVulnWebToServiceASYNC(self, host, srvname, newVuln):
        self.__addPendingAction(modelactions.ADDVULNWEBSRV, host, srvname, newVuln)

    def addVulnWebToServiceSYNC(self, host, srvname, newVuln):
        self._processAction(modelactions.ADDVULNWEBSRV, [host, srvname, newVuln], sync=True)

    def delVulnFromApplicationASYNC(self, hostname, appname, vuln):
        self.__addPendingAction(modelactions.DELVULNAPP, hostname, appname, vuln)

    def delVulnFromApplicationSYNC(self, hostname, appname, vuln):
        self._processAction(modelactions.DELVULNAPP, [hostname, appname, vuln], sync=True)

    def delVulnFromInterfaceASYNC(self, hostname, intname, vuln):
        self.__addPendingAction(modelactions.DELVULNINT, hostname, intname, vuln)

    def delVulnFromInterfaceSYNC(self, hostname, intname, vuln):
        self._processAction(modelactions.DELVULNINT, [hostname,intname, vuln], sync=True)

    def delVulnFromHostASYNC(self, hostId, vulnId):
        self.__addPendingAction(modelactions.DELVULNHOST, vulnId)

    def delVulnFromHostSYNC(self, hostname, vulnId):
        self._processAction(modelactions.DELVULNHOST, [vulnId], sync=True)

    def delVulnFromServiceASYNC(self, hostname, srvname, vulnId):
        self.__addPendingAction(modelactions.DELVULNSRV, vulnId)

    def delVulnFromServiceSYNC(self, hostname, srvname, vulnId):
        self._processAction(modelactions.DELVULNSRV, [vulnId], sync=True)

    def delVulnSYNC(self, model_object, vuln_id):
        self._processAction(modelactions.DELVULN, [vuln_id], sync=True)


    def editVulnSYNC(self, vuln, name, desc, severity, refs):
        self._processAction(modelactions.EDITVULN, [vuln, name, desc, severity, refs], sync=True)

    def editVulnASYNC(self, vuln, name, desc, severity, refs):
        self.__addPendingAction(modelactions.EDITVULN, vuln, name, desc, severity, refs)

    def editVulnWebSYNC(self, vuln, name, desc, website, path, refs, severity,
                        request, response, method, pname, params, query,
                        category):
        self._processAction(modelactions.EDITVULN,
                            [vuln, name, desc, website, path, refs, severity,
                             request, response, method, pname, params, query,
                             category], sync=True)

    def editVulnWebASYNC(self, vuln, name, desc, website, path, refs,
                         severity, request, response, method, pname,
                         params, query, category):
        self.__addPendingAction(modelactions.EDITVULN,
                                vuln, name, desc, website, path, refs,
                                 severity, request, response, method,
                                 pname, params, query, category)

    # Note
    def addNoteToInterfaceASYNC(self, host, intId, newNote):
        self.__addPendingAction(modelactions.ADDNOTEINT, newNote, intId)

    def addNoteToInterfaceSYNC(self, host, intId, newNote):
        self._processAction(modelactions.ADDNOTEINT, [newNote, intId], sync=True)

    def addNoteToApplicationASYNC(self, host, appname, newNote):
        self.__addPendingAction(modelactions.ADDNOTEAPP, host, appname, newNote)

    def addNoteToApplicationSYNC(self, host, appname, newNote):
        self._processAction(modelactions.ADDNOTEAPP, [host, appname, newNote], sync=True)

    def addNoteToHostASYNC(self, hostId, newNote):
        self.__addPendingAction(modelactions.ADDNOTEHOST, newNote, hostId)

    def addNoteToHostSYNC(self, hostId, newNote):
        self._processAction(modelactions.ADDNOTEHOST, [newNote, hostId], sync=True)

    def addNoteToServiceASYNC(self, host, srvId, newNote):
        self.__addPendingAction(modelactions.ADDNOTESRV, newNote, srvId)

    def addNoteToNoteASYNC(self, host, srvname, note_id, newNote):
        self.__addPendingAction(modelactions.ADDNOTENOTE, host, srvname, note_id, newNote)

    def addNoteToNoteSYNC(self, noteId, newNote):
        self._processAction(modelactions.ADDNOTENOTE, [newNote, noteId], sync=True)

    def addNoteToServiceSYNC(self, host, srvId, newNote):
        self._processAction(modelactions.ADDNOTESRV, [newNote, srvId], sync=True)

    def addNoteSYNC(self, model_object, newNote):
        self._processAction(modelactions.ADDNOTE, [newNote, model_object], sync=True)

    def delNoteFromApplicationASYNC(self, hostname, appname, note):
        self.__addPendingAction(modelactions.DELNOTEAPP, hostname, appname, note)

    def delNoteFromApplicationSYNC(self, hostname, appname, note):
        self._processAction(modelactions.DELNOTEAPP, [hostname, appname, note], sync=True)

    def delNoteFromInterfaceASYNC(self, hostname, intname, noteId):
        self.__addPendingAction(modelactions.DELNOTEINT, noteId)

    def delNoteFromInterfaceSYNC(self, hostname, intname, noteId):
        self._processAction(modelactions.DELNOTEINT, [noteId], sync=True)

    def delNoteFromHostASYNC(self, hostId, noteId):
        self.__addPendingAction(modelactions.DELNOTEHOST, noteId)

    def delNoteFromHostSYNC(self, hostname, noteId):
        self._processAction(modelactions.DELNOTEHOST, [noteId], sync=True)

    def delNoteFromServiceASYNC(self, hostId, srvId, noteId):
        self.__addPendingAction(modelactions.DELNOTESRV, noteId)

    def delNoteFromServiceSYNC(self, hostname, srvname, noteId):
        self._processAction(modelactions.DELNOTESRV, [noteId], sync=True)

    def delNoteSYNC(self, model_object, note_id):
        self._processAction(modelactions.DELNOTE, [note_id], sync=True)

    def addCredToServiceASYNC(self, host, srvId, newCred):
        self.__addPendingAction(modelactions.ADDCREDSRV, newCred, srvId)

    def addCredToServiceSYNC(self, host, srvId, newCred):
        self._processAction(modelactions.ADDCREDSRV, [newCred, srvId], sync=True)

    def delCredFromServiceASYNC(self, hostname, srvname, credId):
        self.__addPendingAction(modelactions.DELCREDSRV, credId)

    def delCredFromServiceSYNC(self, hostname, srvname, credId):
        self._processAction(modelactions.DELCREDSRV, [credId], sync=True)


    def editNoteSYNC(self, note, name, text):
        self._processAction(modelactions.EDITNOTE, [note, name, text], sync=True)

    def editNoteASYNC(self, note, name, text):
        self.__addPendingAction(modelactions.EDITNOTE, note, name, text)

    def editCredSYNC(self, cred, username, password):
        self._processAction(modelactions.EDITCRED, [cred, username, password], sync=True)

    def editCredASYNC(self, cred, username, password):
        self.__addPendingAction(modelactions.EDITCRED, cred, username, password)

    def addCredSYNC(self, model_object_id, newCred):
        self._processAction(modelactions.ADDCRED, [newCred, model_object_id], sync=True)

    def delCredSYNC(self, model_object, cred_id):
        self._processAction(modelactions.DELCRED, [cred_id], sync=True)

    def getHost(self, name):
        hosts_mapper= self.mappers_manager.getHostsMapper()
        return hosts_mapper.findObjectByName(name)

    def getHostsCount(self):
        return len(self._hosts)

    def getAllHosts(self, mode=0):
        hosts_mapper = self.mappers_manager.getHostsMapper()
        hosts = hosts_mapper.getAllHosts()
        return hosts

    def setWorkspace(self, workspace):
        self._workspace = workspace
        self._hosts = self._workspace.getContainee()
        self._workspace.load()
        self.createIndex(self._hosts)
        notifier.workspaceChanged(self._workspace)

    def createIndex(self, hosts):
        self.treeWordsTries = TreeWordsTries()
        self.treeWordsTries.clear()
        for k in hosts.keys():
            h = hosts[k]
            self.treeWordsTries.addWord(h.getName())
            for intr in h.getAllInterfaces():
                ipv4 = intr.ipv4
                ipv6 = intr.ipv6
                if not ipv4['address'] in ["0.0.0.0", None]:
                    self.treeWordsTries.addWord(ipv4['address'])

                if not ipv6['address'] in ["0000:0000:0000:0000:0000:0000:0000:0000", None]:
                    self.treeWordsTries.addWord(ipv6['address'])

                for hostname in intr.getHostnames():
                    self.treeWordsTries.addWord(hostname)

    def getWorkspace(self):
        return self._workspace

    def checkPermissions(self, op):
        ## In order to use the decorator passPermissionsOrRaise
        ## The client should implement checkPermissions method.
        self.__sec.checkPermissions(op)

    def getWorkspaceSyncronizer(self):
        return WorkspaceSyncronizer(self.getWorkspace())

    #@passPermissionsOrRaise
    @lockModel
    def syncActiveWorkspace(self):
        if len(self.getWorkspace().getConflicts()):
            #There are some conflicts
            notifier.showPopup("Sync Failed! \nYou should check if there are some conflicts to resolve")
            return False

        ws = self.getWorkspaceSyncronizer()
        if not ws.sync():
            notifier.showPopup("Sync Failed! \nYou should check if there are some conflicts to resolve")
            return False
        notifier.workspaceLoad(self.getAllHosts())
        return True
