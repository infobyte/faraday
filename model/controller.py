'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import time
import logging
import traceback
import model.common  # this is to make sure the factory is created
from multiprocessing import Lock
from Queue import Empty
from threading import Thread

from config.configuration import getInstanceConfiguration
from persistence.server.server_io_exceptions import ConflictInDatabase
from utils.logs import getLogger
import model.api as api
from model.guiapi import notification_center as notifier
from gui.customevents import *
from functools import wraps
from persistence.server import models

# XXX: consider re-writing this module! There's alot of repeated code
# and things are really messy

CONF = getInstanceConfiguration()
logger = logging.getLogger(__name__)


class modelactions:
    ADDHOST = 2000
    DELHOST = 2001
    ADDSERVICEHOST = 2008
    ADDSERVICEHOST = 20008
    ADDCATEGORY = 2011
    ADDVULNHOST = 2017
    DELVULNHOST = 2018
    ADDVULNSRV = 2019
    DELVULNSRV = 2020
    ADDNOTEHOST = 2025
    DELNOTEHOST = 2026
    ADDNOTESRV = 2027
    DELNOTESRV = 2028
    RENAMEROOT = 2029
    ADDNOTEVULN = 2030
    DELNOTEVULN = 2031
    EDITHOST = 2032
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
    PLUGINSTART = 3000
    PLUGINEND = 3001

    __descriptions = {
        ADDHOST: "ADDHOST",
        DELHOST: "DELHOST",
        ADDCATEGORY: "ADDCATEGORY",
        ADDVULNHOST: "ADDVULNHOST",
        DELVULNHOST: "DELVULNHOST",
        ADDVULNSRV: "ADDVULNSRV",
        DELVULNSRV: "DELVULNSRV",
        ADDNOTEVULN: "ADDNOTEVULN",
        DELNOTEVULN: "DELNOTEVULN",
        ADDNOTENOTE: "ADDNOTENOTE",
        DELNOTENOTE: "DELNOTENOTE",
        EDITHOST: "EDITHOST",
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
        DELCRED: "DELCRED",
        PLUGINSTART: "PLUGINSTART",
        PLUGINEND: "PLUGINEND"
    }

    @staticmethod
    def getDescription(action):
        return modelactions.__descriptions.get(action, "")


class ModelController(Thread):

    def __init__(self, mappers_manager, pending_actions):
        Thread.__init__(self)

        self.mappers_manager = mappers_manager

        # set as daemon
#        self.setDaemon(True)

        # flag to stop daemon thread
        self._stop = False
        # locks needed to make model thread-safe
        self._hosts_lock = Lock()

        # count of plugins sending actions
        self.active_plugins_count = 0
        self.active_plugins_count_lock = Lock()

        # TODO: check if it is better using collections.deque
        # a performance analysis should be done
        # http://docs.python.org/library/collections.html#collections.deque

        # the actions queue
        self._pending_actions = pending_actions

        # a reference to the ModelObjectFactory
        self._object_factory = model.common.factory
        self._registerObjectTypes()

        # sync api request flag. This flag is used to let the model know
        # there's some other object trying to use a sync api, and it should
        # give priority to that and stop processing the queue
        self._sync_api_request = False

        # This flag & lock are used when the complete model is being persisted
        self._saving_model_flag = False
        self._saving_model_lock = Lock()

        self._actionDispatcher = None
        self._setupActionDispatcher()

        self.objects_with_updates = []
        self._stop = False

    def __getattr__(self, name):
        getLogger(self).debug("ModelObject attribute to refactor: %s" % name)

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
        self._object_factory.register(models.Host)
        self._object_factory.register(models.Service)
        self._object_factory.register(models.Vuln)
        self._object_factory.register(models.VulnWeb)
        self._object_factory.register(models.Note)
        self._object_factory.register(models.Credential)

    def _checkParent(self, parent_type):
        """Takes a parent_type and returns the appropiate checkParentDecorator,
        a function that takes another function (most probably you are using
        it for the __add method) and checks if the object as a parent of
        parent_type before adding it.
        """
        def checkParentDecorator(add_func):
            @wraps(add_func)
            def addWrapper(new_obj, parent_id=None, *args):
                parent = self.mappers_manager.find(parent_type, parent_id)
                if parent:
                    add_func(new_obj, parent_id, *args)
                else:
                    msg = "A parent is needed for %s objects" % new_obj.class_signature
                    getLogger(self).error(msg)
                    return False
            return addWrapper
        return checkParentDecorator

    def _setupActionDispatcher(self):

        self._actionDispatcher = {
            modelactions.ADDHOST: self.__add,
            modelactions.DELHOST: self.__del,
            modelactions.EDITHOST: self.__edit,
            modelactions.EDITSERVICE: self.__edit,
            # Vulnerability
            modelactions.ADDVULNHOST: self.__add,
            modelactions.DELVULNHOST: self.__del,
            modelactions.ADDVULNSRV: self.__add,
            modelactions.DELVULNSRV: self.__del,
            modelactions.ADDVULN: self.__add,
            modelactions.DELVULN: self.__del,
            modelactions.ADDVULNWEBSRV: self.__add,
            modelactions.EDITVULN: self.__edit,
            #Service
            modelactions.ADDSERVICEHOST: self.__add,
            # Note
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
            modelactions.DELCRED: self.__del,
            # Plugin states
            modelactions.PLUGINSTART: self._pluginStart,
            modelactions.PLUGINEND: self._pluginEnd
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
        # if res: # notify only if action was done successfuly
        #     self._notifyModelUpdated(*parameters)
        # else:
        if not res:
            api.devlog("Action code %d failed. Parameters = %s" %
                    (action, str(parameters)))
        if sync:
            self._sync_api_request = False

    def conflictMissing(self, conflict):
        """
        Conflict missing (Resolved by another one)
        Remove conflict in original object and notify to clients
        """
        conflict.getFirstObject().updateResolved(conflict)
        notifier.conflictUpdate(-1)

    def getConflicts(self):
        conflicts = []
        for obj in self.objects_with_updates:
            conflicts += obj.getUpdates()
        return conflicts

    def resolveConflicts(self):
        notifier.conflictResolution(self.getConflicts())

    def resolveConflict(self, conflict, kwargs):
        if self.__edit(conflict.getFirstObject(), **kwargs):
            conflict.getFirstObject().updateResolved(conflict)
            notifier.conflictUpdate(-1)
            # notifier.editHost(conflict.getFirstObject().getHost())
            # self._notifyModelUpdated()

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

    def stop(self):
        self._stop = True

    def _main(self):
        """
        The main method for the thread.
        The controller will be constantly checking a queue
        to see if new actions were added.
        This will make host addition and removal "thread-safe" and will
        avoid locking components that need to interact with the model
        """
        while not self._stop:
            # check if thread must finish
            # no plugin should be active to stop the controller
            if self._stop and self.active_plugins_count == 0:
                break
            # first we check if there is a sync api request
            # or if the model is being saved/sync'ed
            # or if we have pending duplicated hosts that need to be
            # merged by the userget
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
            # TODO: timeout should be set through config
            current_action = self._pending_actions.get(timeout=2)
            action = current_action[0]
            parameters = current_action[1:]
            # dispatch the action
            self._processAction(action, list(parameters))
        except Empty:
            # if timeout was reached, just let the daemon run again
            # this is done just to be able to test the stop flag
            # because if we don't do it, the daemon will be blocked forever
            pass
        except Exception as ex:
            getLogger(self).debug(
                "something strange happened... unhandled exception?")
            getLogger(self).debug(traceback.format_exc())

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
        try:
            mergeAction = old_object.addUpdate(new_object)
            if mergeAction:
                if old_object not in self.objects_with_updates:
                    self.objects_with_updates.append(old_object)
                notifier.conflictUpdate(1)
                return False
        except:
            api.devlog("(%s).addUpdate(%s, %s) - failed" %
                       (self, old_object, new_object))
            return False
        self.mappers_manager.update(old_object)
        notifier.editHost(old_object)
        return True

    # XXX: THIS DOESNT WORK
    def find(self, obj_id):
        return self.mappers_manager.find(obj_id)

    def _save_new_object(self, new_object, command_id):
        res = self.mappers_manager.save(new_object, command_id)
        new_object.setID(res)
        if res:
            notifier.addObject(new_object)
        return res

    def _handle_conflict(self, old_obj, new_obj):
        if not old_obj.needs_merge(new_obj): return True
        return self.addUpdate(old_obj, new_obj)

    def __add(self, new_obj, command_id=None, *args):
        """
            This method sends requests to the faraday-server.

        :param new_obj:
        :param command_id:
        :param args:
        :return:
        """
        try:
            self._save_new_object(new_obj, command_id)
        except ConflictInDatabase as conflict:
            old_obj = new_obj.__class__(conflict.answer.json()['object'], new_obj._workspace_name)
            new_obj.setID(old_obj.getID())
            return self._handle_conflict(old_obj, new_obj)

    def __edit(self, obj, *args, **kwargs):
        obj.updateAttributes(*args, **kwargs)
        self.mappers_manager.update(obj)
        notifier.editHost(obj)
        return True

    def __del(self, objId, *args):
        obj = self.mappers_manager.find(objId)
        if obj:
            obj_parent = obj.getParent()
            if obj_parent:
                obj_parent.deleteChild(objId)

            self.removeConflictsByObject(obj)

            self.mappers_manager.remove(objId, obj.class_signature)

            if obj.class_signature == models.Host.class_signature:
                notifier.delHost(objId)
            else:
                notifier.editHost(obj.getHost())
            return True
        return False

    def delHostASYNC(self, hostId):
        """
        ASYNC API
        Adds an action to the ModelController actions queue indicating a
        particular host must be removed from the model
        """
        self.__addPendingAction(modelactions.DELHOST, hostId)

    def delHostSYNC(self, hostId):
        """
        SYNC API
        Deletes a host from model
        """
        self._processAction(modelactions.DELHOST, [hostId], sync=True)

    def editHostSYNC(self, host, name, description, os, owned):
        """
        SYNC API
        Modifies a host from model
        """
        self._processAction(modelactions.EDITHOST, [
                            host, name, description, os, owned], sync=True)

    def editServiceSYNC(self, service, name, description, protocol, ports, status, version, owned):
        """
        SYNC API
        Modifies a host from model
        """
        self._processAction(modelactions.EDITSERVICE, [
                            service, name, description, protocol, ports, status, version, owned], sync=True)

    def editServiceASYNC(self, service, name, description, protocol, ports, status, version, owned):
        """
        ASYNC API
        Modifies a service from model
        """
        self.__addPendingAction(modelactions.EDITSERVICE, service,
                                name, description, protocol, ports, status, version, owned)

    def __editService(self, service, name=None, description=None,
                      protocol=None, ports=None, status=None,
                      version=None, owned=None):
        res = False
        if service is not None:
            service.updateAttributes(
                name, description, protocol, ports, status, version, owned)
            notifier.editHost(service.getHost())
            res = True
        return res

    def addPluginStart(self, name):
        self.__addPendingAction(modelactions.PLUGINSTART, name)

    def addPluginEnd(self, name):
        self.__addPendingAction(modelactions.PLUGINEND, name)

    def _pluginStart(self, name):
        self.active_plugins_count_lock.acquire()
        getLogger(self).info("Plugin Started: " + name)
        self.active_plugins_count += 1
        self.active_plugins_count_lock.release()
        return True

    def _pluginEnd(self, name):
        self.active_plugins_count_lock.acquire()
        getLogger(self).info("Plugin Ended: " + name)
        self.active_plugins_count -= 1
        self.active_plugins_count_lock.release()
        return True

    def addVulnToHostASYNC(self, hostId, newVuln):
        self.__addPendingAction(modelactions.ADDVULNHOST, newVuln, hostId)

    def addVulnToHostSYNC(self, hostId, newVuln):
        self._processAction(modelactions.ADDVULNHOST, [
                            newVuln, hostId], sync=True)

    def addVulnToServiceASYNC(self, host, srvId, newVuln):
        self.__addPendingAction(modelactions.ADDVULNSRV, newVuln, srvId)

    def addVulnToServiceSYNC(self, host, srvId, newVuln):
        self._processAction(modelactions.ADDVULNSRV, [
                            newVuln, srvId], sync=True)

    def addVulnSYNC(self, modelObjectId, newVuln):
        self._processAction(modelactions.ADDVULN, [
                            newVuln, modelObjectId], sync=True)

    def addVulnWebToServiceASYNC(self, host, srvId, newVuln):
        self.__addPendingAction(modelactions.ADDVULNWEBSRV, newVuln, srvId)

    def addVulnWebToServiceSYNC(self, host, srvId, newVuln):
        self._processAction(modelactions.ADDVULNWEBSRV,
                            [newVuln, srvId], sync=True)

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

    def editVulnSYNC(self, vuln, name, desc, severity, resolution, refs):
        self._processAction(modelactions.EDITVULN, [
                            vuln, name, desc, severity, resolution, refs], sync=True)

    def editVulnASYNC(self, vuln, name, desc, severity, resolution, refs):
        self.__addPendingAction(modelactions.EDITVULN,
                                vuln, name, desc, severity, resolution, refs)

    def editVulnWebSYNC(self, vuln, name, desc, website, path, refs, severity, resolution,
                        request, response, method, pname, params, query,
                        category):
        self._processAction(modelactions.EDITVULN,
                            [vuln, name, desc, website, path, refs, severity, resolution,
                             request, response, method, pname, params, query, category], sync=True)

    def editVulnWebASYNC(self, vuln, name, desc, website, path, refs,
                         severity, resolution, request, response, method, pname,
                         params, query, category):
        self.__addPendingAction(modelactions.EDITVULN,
                                vuln, name, desc, website, path, refs,
                                severity, resolution, request, response, method,
                                pname, params, query, category)

    def addNoteToHostASYNC(self, hostId, newNote):
        self.__addPendingAction(modelactions.ADDNOTEHOST, newNote, hostId)

    def addNoteToHostSYNC(self, hostId, newNote):
        self._processAction(modelactions.ADDNOTEHOST, [
                            newNote, hostId], sync=True)

    def addNoteToServiceASYNC(self, host, srvId, newNote):
        self.__addPendingAction(modelactions.ADDNOTESRV, newNote, srvId)

    def addNoteToNoteASYNC(self, host, srvname, note_id, newNote):
        self.__addPendingAction(modelactions.ADDNOTENOTE, newNote, note_id)

    def addNoteToNoteSYNC(self, noteId, newNote):
        self._processAction(modelactions.ADDNOTENOTE, [
                            newNote, noteId], sync=True)

    def addNoteToServiceSYNC(self, host, srvId, newNote):
        self._processAction(modelactions.ADDNOTESRV, [
                            newNote, srvId], sync=True)

    def addNoteSYNC(self, model_object, newNote):
        self._processAction(modelactions.ADDNOTE, [
                            newNote, model_object], sync=True)

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
        self._processAction(modelactions.ADDCREDSRV, [
                            newCred, srvId], sync=True)

    def delCredFromServiceASYNC(self, hostname, srvname, credId):
        self.__addPendingAction(modelactions.DELCREDSRV, credId)

    def delCredFromServiceSYNC(self, hostname, srvname, credId):
        self._processAction(modelactions.DELCREDSRV, [credId], sync=True)

    def editNoteSYNC(self, note, name, text):
        self._processAction(modelactions.EDITNOTE, [
                            note, name, text], sync=True)

    def editNoteASYNC(self, note, name, text):
        self.__addPendingAction(modelactions.EDITNOTE, note, name, text)

    def editCredSYNC(self, cred, username, password):
        self._processAction(modelactions.EDITCRED, [
                            cred, username, password], sync=True)

    def editCredASYNC(self, cred, username, password):
        self.__addPendingAction(modelactions.EDITCRED,
                                cred, username, password)

    def addCredSYNC(self, model_object_id, newCred):
        self._processAction(modelactions.ADDCRED, [
                            newCred, model_object_id], sync=True)

    def delCredSYNC(self, model_object, cred_id):
        self._processAction(modelactions.DELCRED, [cred_id], sync=True)

    def newHost(self, ip, os="Unknown"):
        return model.common.factory.createModelObject(
            models.Host.class_signature, ip,
            self.mappers_manager.workspace_name, os=os, parent_id=None)

    def newService(self, name, protocol="tcp?", ports=[], status="running",
                   version="unknown", description="", parent_id=None):
        return model.common.factory.createModelObject(
            models.Service.class_signature, name,
            self.mappers_manager.workspace_name, protocol=protocol, ports=ports, status=status,
            version=version, description=description, parent_id=parent_id)

    def newVuln(self, name, desc="", ref=None, severity="", resolution="",
                confirmed=False, parent_id=None):
        return model.common.factory.createModelObject(
            models.Vuln.class_signature, name,
            self.mappers_manager.workspace_name, desc=desc, ref=ref, severity=severity, resolution=resolution,
            confirmed=confirmed, parent_id=parent_id)

    def newVulnWeb(self, name, desc="", ref=None, severity="", resolution="",
                   website="", path="", request="", response="", method="",
                   pname="", params="", query="", category="", confirmed=False,
                   parent_id=None):
        return model.common.factory.createModelObject(
            models.VulnWeb.class_signature, name,
            self.mappers_manager.workspace_name, desc=desc, ref=ref, severity=severity, resolution=resolution,
            website=website, path=path, request=request, response=response,
            method=method, pname=pname, params=params, query=query,
            category=category, confirmed=confirmed, parent_id=parent_id)

    def newNote(self, name, text, parent_id=None):
        return model.common.factory.createModelObject(
            models.Note.class_signature, name,
            self.mappers_manager.workspace_name, text=text, parent_id=parent_id)

    def newCred(self, username, password, parent_id=None):
        return model.common.factory.createModelObject(
            models.Credential.class_signature, name,
            username, password=password, parent_id=parent_id)

    def getHost(self, name):
        hosts_mapper = self.mappers_manager.getMapper(models.Host.class_signature)
        return hosts_mapper.find(name)

    def getAllHosts(self):
        """Return a list with every host. If there's an exception, assume there
        are no hosts.
        """
        try:
            hosts = self.mappers_manager.getMapper(
                models.Host.class_signature.getAll())
        except:
            hosts = []
        return hosts

    def getWebVulns(self):
        return self.mappers_manager.getMapper(
            models.Vuln.class_signature).getAll()

    def getHostsCount(self):
        """Get how many hosts are in the workspace. If it can't, it will
        return zero."""
        try:
            hosts = models.Hosts.class_signature
            count = self.mappers_manager.getMapper(hosts).getCount()
        except:
            getLogger(self).debug(
                "Couldn't get host count: assuming it is zero.")
            count = 0
        return count

    def getServicesCount(self):
        """Get how many services are in the workspace. If it can't, it will
        return zero."""
        try:
            services = models.Service.class_signature
            count = self.mappers_manager.getMapper(services).getCount()
        except:
            getLogger(self).debug(
                "Couldn't get services count: assuming it is zero.")
            count = 0
        return count

    def getVulnsCount(self):
        """Get how many vulns (web + normal) are in the workspace.
        If it can't, it will return zero."""
        try:
            vulns = models.Vuln.class_signature
            web_vulns = models.WebVuln.class_signature
            count = (self.mappers_manager.getMapper(vulns).getCount() +
                     self.mappers_manager.getMapper(web_vulns).getCount())
        except:
            getLogger(self).debug(
                "Couldn't get vulnerabilities count: assuming it is zero.")
            count = 0
        return count
