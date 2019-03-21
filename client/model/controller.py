'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import time
import logging
import traceback
import faraday.client.model.common  # this is to make sure the factory is created
from multiprocessing import Lock
from Queue import Empty
from threading import Thread

from faraday.config.configuration import getInstanceConfiguration
from faraday.client.model import Modelactions
from faraday.client.persistence.server.server_io_exceptions import ConflictInDatabase
from faraday.utils.logs import getLogger
import faraday.client.model.api as api
from faraday.client.model.guiapi import notification_center as notifier
from faraday.client.gui.customevents import *
from functools import wraps
from faraday.client.persistence.server import models

# XXX: consider re-writing this module! There's alot of repeated code
# and things are really messy

CONF = getInstanceConfiguration()
logger = logging.getLogger(__name__)


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
        self._object_factory = faraday.client.model.common.factory
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
        self.processing = False

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
            Modelactions.ADDHOST: self.__add,
            Modelactions.DELHOST: self.__del,
            Modelactions.EDITHOST: self.__edit,
            Modelactions.EDITSERVICE: self.__edit,
            # Vulnerability
            Modelactions.ADDVULNHOST: self.__add,
            Modelactions.DELVULNHOST: self.__del,
            Modelactions.ADDVULNSRV: self.__add,
            Modelactions.DELVULNSRV: self.__del,
            Modelactions.ADDVULN: self.__add,
            Modelactions.DELVULN: self.__del,
            Modelactions.ADDVULNWEBSRV: self.__add,
            Modelactions.EDITVULN: self.__edit,
            #Service
            Modelactions.ADDSERVICEHOST: self.__add,
            # Note
            Modelactions.ADDNOTEHOST: self.__add,
            Modelactions.DELNOTEHOST: self.__del,
            Modelactions.ADDNOTESRV: self.__add,
            Modelactions.DELNOTESRV: self.__del,
            Modelactions.ADDNOTEVULN: self.__add,
            Modelactions.ADDNOTE: self.__add,
            Modelactions.DELNOTE: self.__del,
            Modelactions.ADDCREDSRV: self.__add,
            Modelactions.DELCREDSRV: self.__del,
            Modelactions.ADDNOTENOTE: self.__add,
            Modelactions.EDITNOTE: self.__edit,
            Modelactions.EDITCRED: self.__edit,
            Modelactions.ADDCRED: self.__add,
            Modelactions.DELCRED: self.__del,
            # Plugin states
            Modelactions.PLUGINSTART: self._pluginStart,
            Modelactions.PLUGINEND: self._pluginEnd,
            Modelactions.DEVLOG: self._devlog,
            Modelactions.LOG: self._log,
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

    def _main(self):
        """
        The main method for the thread.
        The controller will be constantly checking a queue
        to see if new actions were added.
        This will make host addition and removal "thread-safe" and will
        avoid locking components that need to interact with the model
        """

        while not self._stop or self.processing:
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
        for _ in range(self._pending_actions.qsize()):
            self.processAction()

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

    def add_action(self, action):
        self._pending_actions.put(action)

    def __addPendingAction(self, *args):
        """
        Adds a new pending action to the queue
        Action is build with generic args tuple.
        The caller of this function has to build the action in the right
        way since no checks are preformed over args
        """
        new_action = args
        self._pending_actions.put(new_action)

    def addUpdate(self, old_object, new_object, command_id):
        # Returns True if the update was resolved without user interaction
        try:
            mergeAction = old_object.addUpdate(new_object, command_id)
            if mergeAction:
                if old_object not in self.objects_with_updates:
                    self.objects_with_updates.append(old_object)
                notifier.conflictUpdate(1)
                return False
        except Exception as ex:
            api.devlog("(%s).addUpdate(%s, %s) - failed" %
                       (self, old_object, new_object))
            return False
        self.mappers_manager.update(old_object, command_id)
        notifier.editHost(old_object)
        return True

    def find(self, class_signature, obj_id):
        return self.mappers_manager.find(class_signature, obj_id)

    def _save_new_object(self, new_object, command_id):
        res = None
        try:
            res = self.mappers_manager.save(new_object, command_id)
        finally:
            new_object.setID(res)
        if res:
            notifier.addObject(new_object)
        return res

    def _handle_conflict(self, old_obj, new_obj, command_id):
        if not old_obj.needs_merge(new_obj): return True
        return self.addUpdate(old_obj, new_obj, command_id)

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
            return self._handle_conflict(old_obj, new_obj, command_id)
        except Exception as ex:
            logger.exception(ex)
            new_obj.setID(None)
            raise

    def __edit(self, obj, command_id=None, *args, **kwargs):
        obj.updateAttributes(*args, **kwargs)
        self.mappers_manager.update(obj, command_id)
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
        self.__addPendingAction(Modelactions.PLUGINSTART, name)

    def addPluginEnd(self, name):
        self.__addPendingAction(Modelactions.PLUGINEND, name)

    def _pluginStart(self, name, command_id):
        self.active_plugins_count_lock.acquire()
        self.processing = True
        if name not in ["MetasploitOn", "Beef", "Sentinel"]:
            getLogger(self).info("Plugin Started: {0}. ".format(name, command_id))
        self.active_plugins_count += 1
        self.active_plugins_count_lock.release()
        return True

    def _pluginEnd(self, name, command_id):
        self.active_plugins_count_lock.acquire()
        if name not in ["MetasploitOn", "Beef", "Sentinel"]:
            getLogger(self).info("Plugin Ended: {0}".format(name))
        if self.active_plugins_count == 0:
            self.active_plugins_count_lock.release()
            getLogger(self).warn("All plugins ended, but a plugin end action was received.")
            return True
        self.active_plugins_count -= 1
        if self.active_plugins_count == 0:
            self.processing = False
        self.active_plugins_count_lock.release()
        return True

    def _devlog(self, msg, *args, **kwargs):
        # I have no idea what I am doing
        api.devlog(msg)
        return True

    def _log(self, msg, *args, **kwargs):
        # I have no idea what I am doing
        api.log(msg, *args[:-1])
        return True

    def newHost(self, ip, os="Unknown", hostnames=None):
        return faraday.client.model.common.factory.createModelObject(
            models.Host.class_signature, ip,
            workspace_name=self.mappers_manager.workspace_name, os=os, parent_id=None, hostnames=hostnames)

    def newService(self, name, protocol="tcp?", ports=[], status="running",
                   version="unknown", description="", parent_id=None):
        return faraday.client.model.common.factory.createModelObject(
            models.Service.class_signature, name,
            workspace_name=self.mappers_manager.workspace_name, protocol=protocol, ports=ports, status=status,
            version=version, description=description, parent_id=parent_id)

    def newVuln(self, name, desc="", ref=None, severity="", resolution="",
                confirmed=False, parent_id=None):
        return faraday.client.model.common.factory.createModelObject(
            models.Vuln.class_signature, name,
            workspace_name=self.mappers_manager.workspace_name, desc=desc, ref=ref, severity=severity, resolution=resolution,
            confirmed=confirmed, parent_id=parent_id)

    def newVulnWeb(self, name, desc="", ref=None, severity="", resolution="",
                   website="", path="", request="", response="", method="",
                   pname="", params="", query="", category="", confirmed=False,
                   parent_id=None):
        return faraday.client.model.common.factory.createModelObject(
            models.VulnWeb.class_signature, name,
            workspace_name=self.mappers_manager.workspace_name, desc=desc, ref=ref, severity=severity, resolution=resolution,
            website=website, path=path, request=request, response=response,
            method=method, pname=pname, params=params, query=query,
            category=category, confirmed=confirmed, parent_id=parent_id)

    def newNote(self, name, text, parent_id=None, parent_type=None):
        return faraday.client.model.common.factory.createModelObject(
            models.Note.class_signature, name,
            workspace_name=self.mappers_manager.workspace_name, text=text, parent_id=parent_id, parent_type=parent_type)

    def newCred(self, username, password, parent_id=None):
        return faraday.client.model.common.factory.createModelObject(
            models.Credential.class_signature, name,
            username, workspace_name=self.mappers_manager.workspace_name, password=password, parent_id=parent_id)

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
