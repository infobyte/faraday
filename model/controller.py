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
    DELSERVICEHOST = 2008
    ADDAPPLICATION = 2009
    DELAPPLICATION = 2010
    ADDCATEGORY = 2011
    DELCATEGORY = 2012
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
        DELSERVICEHOST: "DELSERVICEHOST",
        ADDAPPLICATION: "ADDAPPLICATION",
        DELAPPLICATION: "DELAPPLICATION",
        ADDCATEGORY: "ADDCATEGORY",
        DELCATEGORY: "DELCATEGORY",
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
            modelactions.DELHOST: self.__delHost,
            modelactions.EDITHOST: self.__editHost,
            modelactions.ADDINTERFACE: self.__add,
            modelactions.DELINTERFACE: self.__delInterfaceFromHost,
            modelactions.EDITINTERFACE: self.__editInterface,
            modelactions.ADDSERVICEINT: self.__addServiceToInterface,
            modelactions.ADDSERVICEAPP: self.__addServiceToApplication,
            modelactions.DELSERVICEINT: self.__delServiceFromInterface,
            modelactions.DELSERVICEAPP: self.__delServiceFromApplication,
            modelactions.DELSERVICEHOST: self.__delService,
            modelactions.EDITSERVICE: self.__editService,
            modelactions.ADDAPPLICATION: self.__addApplication,
            modelactions.DELAPPLICATION:  self.__delApplication,
            modelactions.EDITAPPLICATION: self.__editApplication,
            modelactions.ADDCATEGORY: self.__addCategory,
            modelactions.DELCATEGORY:  self.__delCategory,
            #Vulnerability
            modelactions.ADDVULNINT: self.__addVulnerabilityToInterface,
            modelactions.DELVULNINT: self.__delVulnerabilityFromInterface,
            modelactions.ADDVULNAPP: self.__addVulnerabilityToApplication,
            modelactions.DELVULNAPP: self.__delVulnerabilityFromApplication,
            modelactions.ADDVULNHOST: self.__addVulnerabilityToHost,
            modelactions.DELVULNHOST: self.__delVulnerabilityFromHost,
            modelactions.ADDVULNSRV: self.__addVulnerabilityToService,
            modelactions.DELVULNSRV: self.__delVulnerabilityFromService,
            modelactions.ADDVULN: self.__addVulnToModelObject,
            modelactions.DELVULN: self.__delVulnFromModelObject,
            modelactions.ADDVULNWEBSRV: self.__addVulnerabilityToService,
            modelactions.DELVULNWEBSRV: self.__delVulnerabilityFromService,
            modelactions.EDITVULN: self.__editVulnerability,
            #Note
            modelactions.ADDNOTEINT: self.__addNoteToInterface,
            modelactions.DELNOTEINT: self.__delNoteFromInterface,
            modelactions.ADDNOTEAPP: self.__addNoteToApplication,
            modelactions.DELNOTEAPP: self.__delNoteFromApplication,
            modelactions.ADDNOTEHOST: self.__addNoteToHost,
            modelactions.DELNOTEHOST: self.__delNoteFromHost,
            modelactions.ADDNOTESRV: self.__addNoteToService,
            modelactions.DELNOTESRV: self.__delNoteFromService,
            modelactions.ADDNOTEVULN: self.__addNote,
            modelactions.DELNOTEVULN: self.__delNote,
            modelactions.ADDNOTE: self.__addNoteToModelObject,
            modelactions.DELNOTE: self.__delNoteFromModelObject,
            modelactions.ADDCREDSRV: self.__addCredToService,
            modelactions.DELCREDSRV: self.__delCredFromService,
            modelactions.ADDNOTENOTE: self.__addNoteToServiceNote,
            modelactions.DELNOTENOTE: self.__delNoteFromServiceNote,
            modelactions.EDITNOTE: self.__editNote,
            modelactions.EDITCRED: self.__editCred,
            modelactions.ADDCRED: self.__addCredToModelObject,
            modelactions.DELCRED: self.__delCredFromModelObject
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
        self._processAction(modelactions.ADDHOST, [host, category, update, old_hostname], sync=True)

    def __add(self,  obj, parent_id=None, *args):
        dataMapper = self.mappers_manager.getMapper(obj)
        object_parent = self.mappers_manager.findObject(parent_id)
        object_parent.addChild(obj.getID(), obj)
        dataMapper.saveObject(obj) 
        self.treeWordsTries.addWord(obj.getName())
        notifier.addHost(obj)


    def delHostASYNC(self, host):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular host must be removed from the model
        """
        self.__addPendingAction(modelactions.DELHOST, host)

    def delHostSYNC(self, host):
        """
        SYNC API
        Deletes a host from model
        """
        self._processAction(modelactions.DELHOST, [host], sync=True)

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

    def __delHost(self, host_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            #res = self._delValue("_hosts", host.getID())
            #if res:
            self.__clearHost(host)
            #this next method removes the host
            self._workspace.remove(host)
            self.treeWordsTries.removeWord(host.getName())
            for i in host.getAllInterfaces():
                for h in i.getHostnames():
                    self.treeWordsTries.removeWord(h)
            notifier.delHost(host.getID())
            res = True

        return res

    def _delValue(self, attrName, valID):
        # attribute passed as a parameter MUST BE  the name
        # of an internal attribute which is a dictionary indexed
        # with a string ID
        api.devlog("(%s)._delValue(%s, %s)" % (self, attrName, valID))
        ref = self.__getattribute__(attrName)
        api.devlog("ref.keys() = %s" % ref.keys())
        if valID in ref:
            del ref[valID]
            return True

        hash_id = get_hash([valID])
        if hash_id in ref:
            del ref[hash_id]
            return True

        for element in ref.itervalues():
            if valID == element.name:
                del ref[element.getID()]
                return True

        # none of the ids were found
        return False

    def editHostSYNC(self, host, name, description, os, owned):
        """
        SYNC API
        Modifies a host from model
        """
        self._processAction(modelactions.EDITHOST, [host, name, description, os, owned], sync=True)

    def __editHost(self, host, name=None, description=None, os=None, owned=None):
        res = False
        #host = self._getValueByID("_hosts", host)
        if host is not None:
            host.updateAttributes(name, description, os, owned)
            res = True
            notifier.editHost(host)
        return res

    def addInterfaceASYNC(self, host, interface, update=False):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        new interface must be added to a specific host
        """
        self.__addPendingAction(modelactions.ADDINTERFACE, host, interface)

    def addInterfaceSYNC(self, hostId, interface, update=False):
        """
        SYNC API
        Adds interface directly to the model
        """
        self._processAction(modelactions.ADDINTERFACE, [interface, hostId], sync=True)

    def __addInterfaceToHost(self, host_id, interface):
        res = False
        #self.__acquire_host_lock()
        # if host is not found nothing is done with the new interface
        try:
            host = self._getValueByID("_hosts", host_id)
            if host is not None:
                old_interface = host.getInterface(interface.getID())
                if old_interface:
                    res = self.addUpdate(old_interface, interface)
                else:
                    res = host.addInterface(interface)

                if res:
                    self.treeWordsTries.addWord(interface.name)
                    for h in interface.getHostnames():
                        self.treeWordsTries.addWord(h)
                    notifier.editHost(host)
        except Exception as e:
            raise e
        #self.__release_host_lock()
        return res

    def delInterfaceASYNC(self, host, interface_name):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular host must be removed from the model
        """
        self.__addPendingAction(modelactions.DELINTERFACE, host, interface_name)

    def delInterfaceSYNC(self, host, interface_name):
        """
        SYNC API
        Deletes an interface from model
        """
        self._processAction(modelactions.DELINTERFACE, [host, interface_name], sync=True)

    def __delInterfaceFromHost(self, host_id, interface_id):
        res = False
        #self.__acquire_host_lock()
        # DO NOT USE self.getHost because it will cause a deadlock
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            interface = host.getInterface(interface_id)
            if interface is not None:
                res = host.delInterface(interface.getID())
                self.__clearInterface(interface)
                self.treeWordsTries.removeWord(interface.name)
                for h in interface.getHostnames():
                    self.treeWordsTries.removeWord(h)
                notifier.editHost(host)

        return res

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

    def __editInterface(self, interface, name, description, hostnames,
                        mac, ipv4, ipv6, network_segment,
                        amount_ports_opened, amount_ports_closed,
                        amount_ports_filtered, owned):
        res = False
        if interface is not None:
            interface.updateAttributes(name, description, hostnames, mac,
                                       ipv4, ipv6, network_segment,
                                       amount_ports_opened,
                                       amount_ports_closed,
                                       amount_ports_filtered, owned)

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
            notifier.editHost(interface.getHost())
            res = True
        return res

    def addApplicationASYNC(self, host, application):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        new application must be added to a specific host
        """
        self.__addPendingAction(modelactions.ADDAPPLICATION, host, application)

    def addApplicationSYNC(self, host, application):
        """
        SYNC API
        Adds an application to a specific host
        directly to the model
        """
        self._processAction(modelactions.ADDAPPLICATION, [host, application], sync=True)

    def __addApplication(self, host_id, application):
        res = False
        #self.__acquire_host_lock()
        # if host is not found nothing is done with the new interface
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            old_application = host.getApplication(application.getID())
            if old_application:
                res = self.addUpdate(old_application, application)
            else:
                res = host.addApplication(application)
                notifier.editHost(host)
        #self.__release_host_lock()
        return res

    def delApplicationASYNC(self, host, app_name):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular host must be removed from the model
        """
        self.__addPendingAction(modelactions.DELAPPLICATION, host, app_name)

    def delApplicationSYNC(self, host, app_name):
        """
        SYNC API
        Deletes an application from the model
        """
        self._processAction(modelactions.DELAPPLICATION, [host, app_name], sync=True)

    def __delApplication(self, host_id, app_id):
        res = False
        #self.__acquire_host_lock()
        # DO NOT USE self.getHost because it will cause a deadlock
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            application = host.getApplication(app_id)
            if application is not None:
                self.__clearApplication(application)
                res = host.delApplication(application.getID())
                notifier.editHost(host)

        #self.__release_host_lock()
        return res

    def editApplicationSYNC(self, application, name, description, status, version, owned):
        """
        SYNC API
        Modifies a host from model
        """
        self._processAction(modelactions.EDITAPPLICATION, [application, name, description, status, version, owned], sync=True)

    def __editApplication(self, application, name=None, description=None, status=None, version=None, owned=None):
        res = False
        #host = self._getValueByID("_hosts", host)
        if application is not None:
            application.updateAttributes(name, description, status, version, owned)
            notifier.editHost(application.getHost())
            res = True
        return res

    def addServiceToInterfaceASYNC(self, host, interface_name, newService):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        new services must be added to a specific host in a specific interface
        """
        self.__addPendingAction(modelactions.ADDSERVICEINT, host, interface_name, newService)

    def addServiceToInterfaceSYNC(self, host_id, interface_id, newService):
        """
        SYNC API
        Adds a service to a specific host in a specific interface
        directly to the model
        """
        self._processAction(modelactions.ADDSERVICEINT, [host_id, interface_id, newService], sync=True)

    def addServiceToApplicationASYNC(self, host, appname, newService):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        new services must be added to a specific host in a specific interface
        """
        self.__addPendingAction(modelactions.ADDSERVICEAPP, host, appname, newService)

    def addServiceToApplicationSYNC(self, host, appname, newService):
        """
        SYNC API
        Adds a service to a specific host in a specific application
        directly to the model
        """
        self._processAction(modelactions.ADDSERVICEAPP, [host, appname, newService], sync=True)

    def __addServiceToInterface(self, host_id, interface_id, service):
        res = False
        #self.__acquire_host_lock()
        # if host is not found nothing is done with the new interface
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            interface = host.getInterface(interface_id)
            if interface is not None:
                old_service = interface.getService(service.getID())
                if old_service:
                    res = self.addUpdate(old_service, service)
                else:
                    res = interface.addService(service)
                    if res:
                        notifier.editHost(host)
        else:
            api.devlog("__addService failed. Host ID: %s not found" % host_id)
        return res

    def __addServiceToApplication(self, host_id, application_id, service):
        res = False
        #self.__acquire_host_lock()
        # if host is not found nothing is done with the new interface
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            application = host.getApplication(application_id)
            if application is not None:
                old_service = application.getService(service.getID())
                if old_service:
                    res = self.addUpdate(old_service, service)
                else:
                    res = application.addService(service)
                    if res:
                        notifier.editHost(host)
        else:
            api.devlog("__addService failed. Host ID: %s not found" % host_id)
        return res

    def delServiceFromInterfaceASYNC(self, host, interface, service):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular service in a host and interface must be removed from the
        model Interface parameter can be "ALL"
        """
        self.__addPendingAction(modelactions.DELSERVICEINT, host, interface, service)

    def delServiceFromInterfaceSYNC(self, host, interface, service):
        """
        SYNC API
        Delete a service in a host and interface from the model
        """
        self._processAction(modelactions.DELSERVICEINT, [host, interface, service], sync=True)

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

    def delServiceFromHostASYNC(self, host, service):
        self.__addPendingAction(modelactions.DELSERVICEHOST, host, service)

    def delServiceFromHostSYNC(self, host, service):
        """
        SYNC API
        Delete a service from the model
        """
        self._processAction(modelactions.DELSERVICEHOST, [host, service], sync=True)

    def __delServiceFromInterface(self, host_id, interface_id=None, service_id=None):
        res = False
        api.devlog("ModelController.__delServiceFromInterface(%s, %s, %s)" %
                  (host_id, interface_id, service_id))
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            if service_id is not None:
                interface = host.getInterface(interface_id)
                if interface is not None:
                    service = interface.getService(service_id)
                    self.__clearService(service)
                    res = interface.delService(service_id)
                    if res:
                        notifier.editHost(host)
        return res

    def __delServiceFromApplication(self, host_id, application_id=None, service_id=None):
        res = False
        api.devlog("ModelController.__delService(%s, %s, %s)" %
                  (host_id, application_id, service_id))
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            if service_id is not None and item_id is not None:
                application = host.getInterface(application_id)
                if application is not None:
                    service = interface.getService(service_id)
                    self.__clearService(service)
                    res = application.delService(service_id)
                    if res:
                        notifier.editHost(host)
        return res

    def __delService(self, host_id, service_id=None):
        res = False
        api.devlog("ModelController.__delService(%s, %s)" %
                  (host_id, service_id))
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            self.__clearService(service)
            res = host.delService(service_id)
            if res:
                notifier.editHost(host)

        return res

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
        self.__addPendingAction(modelactions.EDITSERVICE, [service, name, description, protocol, ports, status, version, owned])

    def __editService(self, service, name=None, description=None,
                      protocol=None, ports=None, status=None,
                      version=None, owned=None):
        res = False
        if service is not None:
            service.updateAttributes(name, description, protocol, ports, status, version, owned)
            notifier.editHost(service.getHost())
            res = True
        return res

    def addVulnToInterfaceASYNC(self, host, intname, newVuln):
        self.__addPendingAction(modelactions.ADDVULNINT, host, intname, newVuln)

    def addVulnToInterfaceSYNC(self, host, intname, newVuln):
        self._processAction(modelactions.ADDVULNINT, [host, intname, newVuln], sync=True)

    def addVulnToApplicationASYNC(self, host, appname, newVuln):
        self.__addPendingAction(modelactions.ADDVULNAPP, host, appname, newVuln)

    def addVulnToApplicationSYNC(self, host, appname, newVuln):
        self._processAction(modelactions.ADDVULNAPP, [host, appname, newVuln], sync=True)

    def addVulnToHostASYNC(self, host, newVuln):
        self.__addPendingAction(modelactions.ADDVULNHOST, host, newVuln)

    def addVulnToHostSYNC(self, host, newVuln):
        self._processAction(modelactions.ADDVULNHOST, [host, newVuln], sync=True)

    def addVulnToServiceASYNC(self, host, srvname, newVuln):
        self.__addPendingAction(modelactions.ADDVULNSRV, host, srvname, newVuln)

    def addVulnToServiceSYNC(self, host, srvname, newVuln):
        self._processAction(modelactions.ADDVULNSRV, [host, srvname, newVuln], sync=True)

    def addVulnSYNC(self, model_object, newVuln):
        self._processAction(modelactions.ADDVULN, [model_object, newVuln], sync=True)

    def addVulnWebToServiceASYNC(self, host, srvname, newVuln):
        self.__addPendingAction(modelactions.ADDVULNWEBSRV, host, srvname, newVuln)

    def addVulnWebToServiceSYNC(self, host, srvname, newVuln):
        self._processAction(modelactions.ADDVULNWEBSRV, [host, srvname, newVuln], sync=True)

    def __addVulnToModelObject(self, model_object, vuln=None):
        res = False
        if model_object is not None:
            old_vuln = model_object.getVuln(vuln.getID())
            if old_vuln:
                res = self.addUpdate(old_vuln, vuln)
            else:
                res = model_object.addVuln(vuln)
                if res:
                    notifier.editHost(model_object.getHost())
        return res

    def __addVulnerabilityToHost(self, host_id, vuln=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None and vuln is not None:
            old_vuln = host.getVuln(vuln.getID())
            if old_vuln:
                res = self.addUpdate(old_vuln, vuln)
            else:
                res = host.addVuln(vuln)
                if res:
                    notifier.editHost(host)
        api.devlog("__addVulnerabilityToHost result = %s" % res)
        return res

    def __addVulnerabilityToApplication(self, host_id, application_id, vuln=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None and application_id is not None and vuln is not None:
            application = host.getApplication(application_id)
            if application is not None:
                old_vuln = application.getVuln(vuln.getID())
                if old_vuln:
                    res = self.addUpdate(old_vuln, vuln)
                else:
                    res = application.addVuln(vuln)
                    if res:
                        notifier.editHost(application.getHost())
        api.devlog("__addVulnerabilityToApplication result = %s" % res)
        return res

    def __addVulnerabilityToInterface(self, host_id, interface_id, vuln=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None and interface_id is not None and vuln is not None:
            interface = host.getInterface(interface_id)
            if interface is not None:
                old_vuln = interface.getVuln(vuln.getID())
                if old_vuln:
                    res = self.addUpdate(old_vuln, vuln)
                else:
                    res = interface.addVuln(vuln)
                    if res:
                        notifier.editHost(interface.getHost())
        api.devlog("__addVulnerabilityToInterface result = %s" % res)
        return res

    def __addVulnerabilityToService(self, host_id, service_id, vuln=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None and service_id is not None and vuln is not None:
            service = host.getService(service_id)
            if service is not None:
                old_vuln = service.getVuln(vuln.getID())
                if old_vuln:
                    res = self.addUpdate(old_vuln, vuln)
                else:
                    res = service.addVuln(vuln)
                    if res:
                        notifier.editHost(service.getHost())
        api.devlog("__addVulnerabilityToService result = %s" % res)
        return res

    def delVulnFromApplicationASYNC(self, hostname, appname, vuln):
        self.__addPendingAction(modelactions.DELVULNAPP, hostname, appname, vuln)

    def delVulnFromApplicationSYNC(self, hostname, appname, vuln):
        self._processAction(modelactions.DELVULNAPP, [hostname, appname, vuln], sync=True)

    def delVulnFromInterfaceASYNC(self, hostname, intname, vuln):
        self.__addPendingAction(modelactions.DELVULNINT, hostname, intname, vuln)

    def delVulnFromInterfaceSYNC(self, hostname, intname, vuln):
        self._processAction(modelactions.DELVULNINT, [hostname,intname, vuln], sync=True)

    def delVulnFromHostASYNC(self, hostname, vuln):
        self.__addPendingAction(modelactions.DELVULNHOST, hostname, vuln)

    def delVulnFromHostSYNC(self, hostname, vuln):
        self._processAction(modelactions.DELVULNHOST, [hostname, vuln], sync=True)

    def delVulnFromServiceASYNC(self, hostname, srvname, vuln):
        self.__addPendingAction(modelactions.DELVULNSRV, hostname, srvname, vuln)

    def delVulnFromServiceSYNC(self, hostname, srvname, vuln):
        self._processAction(modelactions.DELVULNSRV, [hostname, srvname, vuln], sync=True)

    def delVulnSYNC(self, model_object, vuln_id):
        self._processAction(modelactions.DELVULN, [model_object, vuln_id], sync=True)

    def __delVulnFromModelObject(self, model_object, vuln_id):
        res = False
        if model_object is not None:
            vuln = model_object.getVuln(vuln_id)
            self.__clearVuln(vuln)
            res = model_object.delVuln(vuln_id)
            if res:
                notifier.editHost(model_object.getHost())
        return res

    def __delVulnerabilityFromHost(self, host_id, vuln_id):
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            res = host.deleteChild(vuln_id)
            if res:
                notifier.editHost(host)
        return res

    def __delVulnerabilityFromInterface(self, host_id, interface_id, vuln_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            interface = host.getInterface(interface_id)
            if interface is not None:
                res = interface.deleteChild(vuln_id)
                if res:
                    notifier.editHost(host)
        return res

    def __delVulnerabilityFromApplication(self, host_id, application_id, vuln_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            application = host.getApplication(application_id)
            if application is not None:
                vuln = application.getVuln(vuln_id)
                self.__clearVuln(vuln)
                res = application.delVuln(vuln_id)
                if res:
                    notifier.editHost(host)
        return res

    def __delVulnerabilityFromService(self, host_id, service_id, vuln_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            if service is not None:
                res = service.deleteChild(vuln_id)
                if res:
                    notifier.editHost(host)
        return res

    def editVulnSYNC(self, vuln, name, desc, severity, refs):
        self._processAction(modelactions.EDITVULN, [vuln, name, desc, severity, refs], sync=True)

    def editVulnASYNC(self, vuln, name, desc, severity, refs):
        self.__addPendingAction(modelactions.EDITVULN, [vuln, name, desc, severity, refs])

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
                                [vuln, name, desc, website, path, refs,
                                 severity, request, response, method,
                                 pname, params, query, category])

    def __editVulnerability(self, vuln, *args):
        res = False
        if vuln is not None:
            vuln.updateAttributes(*args)
            res = True
            if res:
                notifier.editHost(vuln.getHost())
        return res

    # Note
    def addNoteToInterfaceASYNC(self, host, intname, newNote):
        self.__addPendingAction(modelactions.ADDNOTEINT, host, intname, newNote)

    def addNoteToInterfaceSYNC(self, host, intname, newNote):
        self._processAction(modelactions.ADDNOTEINT, [host, intname, newNote], sync=True)

    def addNoteToApplicationASYNC(self, host, appname, newNote):
        self.__addPendingAction(modelactions.ADDNOTEAPP, host, appname, newNote)

    def addNoteToApplicationSYNC(self, host, appname, newNote):
        self._processAction(modelactions.ADDNOTEAPP, [host, appname, newNote], sync=True)

    def addNoteToHostASYNC(self, host, newNote):
        self.__addPendingAction(modelactions.ADDNOTEHOST, host, newNote)

    def addNoteToHostSYNC(self, host, newNote):
        self._processAction(modelactions.ADDNOTEHOST, [host, newNote], sync=True)

    def addNoteToServiceASYNC(self, host, srvname, newNote):
        self.__addPendingAction(modelactions.ADDNOTESRV, host, srvname, newNote)

    def addNoteToNoteASYNC(self, host, srvname, note_id, newNote):
        self.__addPendingAction(modelactions.ADDNOTENOTE, host, srvname, note_id, newNote)

    def addNoteToServiceSYNC(self, host, srvname, newNote):
        self._processAction(modelactions.ADDNOTESRV, [host, srvname, newNote], sync=True)

    def addNoteSYNC(self, model_object, newNote):
        self._processAction(modelactions.ADDNOTE, [model_object, newNote], sync=True)

    def delNoteFromApplicationASYNC(self, hostname, appname, note):
        self.__addPendingAction(modelactions.DELNOTEAPP, hostname, appname, note)

    def delNoteFromApplicationSYNC(self, hostname, appname, note):
        self._processAction(modelactions.DELNOTEAPP, [hostname, appname, note], sync=True)

    def delNoteFromInterfaceASYNC(self, hostname, intname, note):
        self.__addPendingAction(modelactions.DELNOTEINT, hostname, intname, note)

    def delNoteFromInterfaceSYNC(self, hostname, intname, note):
        self._processAction(modelactions.DELNOTEINT, [hostname, intname, note], sync=True)

    def delNoteFromHostASYNC(self, hostname, note):
        self.__addPendingAction(modelactions.DELNOTEHOST, hostname, note)

    def delNoteFromHostSYNC(self, hostname, note):
        self._processAction(modelactions.DELNOTEHOST, [hostname, note], sync=True)

    def delNoteFromServiceASYNC(self, hostname, srvname, note):
        self.__addPendingAction(modelactions.DELNOTESRV, hostname, srvname, note)

    def delNoteFromServiceSYNC(self, hostname, srvname, note):
        self._processAction(modelactions.DELNOTESRV, [hostname, srvname, note], sync=True)

    def delNoteSYNC(self, model_object, note_id):
        self._processAction(modelactions.DELNOTE, [model_object, note_id], sync=True)

    def addCredToServiceASYNC(self, host, srvname, newCred):
        self.__addPendingAction(modelactions.ADDCREDSRV, host, srvname, newCred)

    def addCredToServiceSYNC(self, host, srvname, newCred):
        self._processAction(modelactions.ADDCREDSRV, [host, srvname, newCred], sync=True)

    def delCredFromServiceASYNC(self, hostname, srvname, cred):
        self.__addPendingAction(modelactions.DELCREDSRV, hostname, srvname, cred)

    def delCredFromServiceSYNC(self, hostname, srvname, note):
        self._processAction(modelactions.DELCREDSRV, [hostname, srvname, cred], sync=True)

    def __addNote(self, action, host_name, item_name=None, note=None, note_id=None):
        res = False
        #self.__acquire_host_lock()
        # if host is not found nothing is done with the new interface
        host = self._getValueByID("_hosts", host_name)
        if host is not None:
            if action == modelactions.ADDNOTEHOST:
                res = host.addNote(note)
            else:
                if action == modelactions.ADDNOTEAPP:
                    _getOne = host.getApplication
                elif action == modelactions.ADDNOTEINT:
                    _getOne = host.getInterface
                elif action == modelactions.ADDNOTESRV:
                    _getOne = host.getService
                elif action == modelactions.ADDNOTENOTE:
                    service = host.getService(item_name)
                    _getOne = service.getNote
                    item_name = note_id

                item = _getOne(item_name)
                if item is not None:
                    res = item.addNote(note)
                else:
                    api.devlog("__addNote: GetNote ID error" + str(item))
            notifier.editHost(host)

        else:
            api.devlog("__addNote failed. Hostname: %s not found" % host_name)
        return res

    def __addNoteToModelObject(self, model_object, note=None):
        res = False
        if model_object is not None:
            old_note = model_object.getNote(note.getID())
            if old_note:
                res = self.addUpdate(old_note, note)
            else:
                res = model_object.addNote(note)
                if res:
                    notifier.editHost(model_object.getHost())
        return res

    def __addNoteToHost(self, host_id, note=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            old_note = host.getNote(note.getID())
            if old_note:
                res = self.addUpdate(old_note, note)
            else:
                res = host.addNote(note)
                if res:
                    notifier.editHost(host)
        else:
            api.devlog("__addNoteToHost failed. Hostname: %s not found" %
                       host_id)
        return res

    def __addNoteToInterface(self, host_id, interface_id, note=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            interface = host.getInterface(interface_id)
            if interface is not None:
                old_note = interface.getNote(note.getID())
                if old_note:
                    res = self.addUpdate(old_note, note)
                else:
                    res = interface.addNote(note)
                    if res:
                        notifier.editHost(host)
        else:
            api.devlog("__addNote failed. Host ID: %s not found" % host_id)
        return res

    def __addNoteToService(self, host_id, service_id, note=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            if service is not None:
                old_note = service.getNote(note.getID())
                if old_note:
                    res = self.addUpdate(old_note, note)
                else:
                    res = service.addNote(note)
                    if res:
                        notifier.editHost(host)
        else:
            api.devlog("__addNote failed. Host ID: %s not found" % host_id)
        return res

    def __addNoteToServiceNote(self, host_id, service_id, note_id, note=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            if service is not None:
                service_note = service.getNote(note_id)
                if note is not None:
                    old_note = service_note.getNote(note.getID())
                    if old_note:
                        res = self.addUpdate(old_note, note)
                    else:
                        res = service_note.addNote(note)
                        if res:
                            notifier.editHost(host)
        else:
            api.devlog("__addNote failed. Host ID: %s not found" % host_id)
        return res

    #DEPRECTED METHOD
    def __delNote(self, action, host_name, item_name, note_id):

        res = False
        # DO NOT USE self.getHost because it will cause a deadlock
        # if interface name is ALL then we delete the service from
        # the whole host
        host = self._getValueByID("_hosts", host_name)
        if host is not None:
            if action == modelactions.DELNOTEHOST:
                res = host.delNote(note_id)
            else:

                if action == modelactions.DELNOTEAPP:
                    _getOne = host.getApplication
                    _getAll = host.getAllApplications
                    _delItem = host.delApplication
                elif action == modelactions.DELNOTEINT:
                    _getOne = host.getInterface
                    _getAll = host.getAllInterfaces
                    _delItem = host.delInterface
                elif action == modelactions.DELNOTESRV:
                    _getOne = host.getService
                    _getAll = host.getAllServices
                    _delItem = host.delService

                if item_name != "ALL":
                    item = _getOne(item_name)
                    # if the service is really in that interface we delete it
                    # since there are cross references we have to delete the
                    # service from the interface and if there aren't any other references
                    # in any other interface then delete it from the host
                    if item is not None:
                        res = item.delNote(note_id)
                else:
                    # remove from all interfaces
                    for item in _getAll():
                        res = item.delNote(service.getID())
            notifier.editHost(host)

        self.__release_host_lock()
        return res

    def __delNoteFromModelObject(self, model_object, note_id):
        res = False
        if model_object is not None:
            note = model_object.getNote(note_id)
            self.__clearNote(note)
            res = model_object.delNote(note_id)
            if res:
                notifier.editHost(model_object.getHost())
        return res

    def __delNoteFromHost(self, host_id, note_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            note = host.getNote(note_id)
            self.__clearNote(note)
            res = host.delNote(note_id)
            if res:
                notifier.editHost(host)
        return res

    def __delNoteFromInterface(self, host_id, interface_id, note_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            interface = host.getInterface(interface_id)
            if interface is not None:
                note = interface.getNote(note_id)
                self.__clearNote(note)
                res = interface.delNote(note_id)
                if res:
                    notifier.editHost(host)
        return res

    def __delNoteFromApplication(self, host_id, application_id, note_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            application = host.getApplication(application_id)
            if application is not None:
                note = application.getNote(note_id)
                self.__clearNote(note)
                res = application.delNote(note_id)
                if res:
                    notifier.editHost(host)
        return res

    def __delNoteFromService(self, host_id, service_id, note_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            if service is not None:
                note = service.getNote(note_id)
                self.__clearNote(note)
                res = service.delNote(note_id)
                if res:
                    notifier.editHost(host)
        return res

    def __delNoteFromServiceNote(self, host_id, service_id, note_id, deep_note_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            if service is not None:
                note = service.getNote(note_id)
                if note is not None:
                    deep_note = note.getNote(note_id)
                    self.__clearNote(deep_note)
                    res = note.delNote(deep_note_id)
                    if res:
                        notifier.editHost(host)
        return res

    def editNoteSYNC(self, note, name, text):
        self._processAction(modelactions.EDITNOTE, [note, name, text], sync=True)

    def editNoteASYNC(self, note, name, text):
        self.__addPendingAction(modelactions.EDITNOTE, [note, name, text])

    def __editNote(self, note, name=None, text=None):
        res = False
        if note is not None:
            note.updateAttributes(name, text)
            res = True
            if res:
                notifier.editHost(note.getHost())
        return res

    def editCredSYNC(self, cred, username, password):
        self._processAction(modelactions.EDITCRED, [cred, username, password], sync=True)

    def editCredASYNC(self, cred, username, password):
        self.__addPendingAction(modelactions.EDITCRED, [cred, username, password])

    def __editCred(self, cred, username=None, password=None):
        res = False
        if cred is not None:
            cred.updateAttributes(username, password)
            res = True
            if res:
                notifier.editHost(cred.getHost())
        return res

    def addCredSYNC(self, model_object, newCred):
        self._processAction(modelactions.ADDCRED, [model_object, newCred], sync=True)

    def __addCredToModelObject(self, model_object, cred=None):
        res = False
        if model_object is not None:
            old_cred = model_object.getCred(cred.getID())
            if old_cred:
                res = self.addUpdate(old_cred, cred)
            else:
                res = model_object.addCred(cred)
                if res:
                    notifier.editHost(model_object.getHost())
        return res

    def delCredSYNC(self, model_object, cred_id):
        self._processAction(modelactions.DELCRED, [model_object, cred_id], sync=True)

    def __delCredFromModelObject(self, model_object, cred_id):
        res = False
        if model_object is not None:
            cred = model_object.getCred(cred_id)
            self.__clearCred(cred)
            res = model_object.delCred(cred_id)
            if res:
                notifier.editHost(model_object.getHost())
        return res

    def __addCredToService(self, host_id, service_id, cred=None):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            if service is not None:
                old_cred = service.getCred(cred.getID())
                if old_cred:
                    res = self.addUpdate(old_cred, cred)
                else:
                    res = service.addCred(cred)
                    if res:
                        notifier.editHost(host)
        else:
            api.devlog("__addCred failed. Host ID: %s not found" % host_id)
        return res

    def __delCredFromService(self, host_id, service_id, cred_id):
        res = False
        host = self._getValueByID("_hosts", host_id)
        if host is not None:
            service = host.getService(service_id)
            if service is not None:
                cred = service.getCred(cred_id)
                self.__clearCred(cred)
                res = service.delCred(cred_id)
                if res:
                    notifier.editHost(host)
        return res

    def getHost(self, name):
        self.__acquire_host_lock()
        h = self._getValueByID("_hosts", name)
        self.__release_host_lock()
        return h

    def getHostsCount(self):
        return len(self._hosts)

    def getAllHosts(self, mode=0):
        """
        return all interfaces in this host
        mode = 0 returns a list of hosts objects
        mode = 1 returns a dictionary of hosts objects with their id as key
        """
        #TODO: this can be a problem because if a host is deleted
        # while another is using this host list, then the information
        # provided here would be wrong
        self.__acquire_host_lock()
        #hosts = self.__getattribute__("_hosts").getContainer()
        hosts = self.__getattribute__("_hosts").values()
        self.__release_host_lock()
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
