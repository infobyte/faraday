#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from utils.logs import getLogger
from utils.decorators import trap_timeout
from config.configuration import getInstanceConfiguration
import threading
import traceback
from urlparse import urlparse
from couchdbkit import Server, ChangesStream, Database, designer
from couchdbkit.resource import ResourceNotFound
import time
import os
import sys
import re
import imp
import plugins.core 
import mockito
from model.common import ModelObject

CONF = getInstanceConfiguration()


class CommandManager(object):
    """ A Command Persistence Manager """
    def __init__(self): 
        self._manager = PersistenceManagerFactory.getInstance()

    def saveCommand(self, command_info):
        return self._manager.saveDocument(command_info.workspace,
                    command_info.toDict())

class PersistenceManagerFactory(object):
    """Creates PersistenceManager
    if CouchDB Available returns a couchdb manager
    otherwise FBManager"""
    instance = None
    def __init__(self):
        pass

    @staticmethod
    def getInstance():
        if PersistenceManagerFactory.instance: 
            return PersistenceManagerFactory.instance
        persistence_manager = CouchdbManager(uri = CONF.getCouchURI()) 
        PersistenceManagerFactory.instance = persistence_manager
        if persistence_manager.isAvailable():
            PersistenceManagerFactory.instance = persistence_manager
            return persistence_manager

class PersistenceManager(object):
    def waitForDBChange(self, db_name, since = 0, timeout = 15000):
        time.sleep(timeout)
        return False

class FSManager(PersistenceManager):
    """ This is a file system manager for the workspace, it will load from the provided FS"""
    def __init__(self, path):
        self._path = path 
        if not os.path.exists(self._path):
            os.mkdir(self._path)

    def removeWorkspace(self, name):
        shutil.rmtree(os.path.join(self._path))

    def removeObject(self, obj_id):
        path = os.path.join(self._path, "%s.json" % obj_id)
        if os.path.isfile(path):
            os.remove(path)

class NoCouchDBError(Exception): pass

class NoConectionServer(object):
    """ Default to this server if no conectivity"""
    def create_db(*args): pass
    def all_dbs(*args, **kwargs): return []
    def get_db(*args): 
        db_mock = mockito.mock(Database)
        mockito.when(db_mock).documents().thenReturn([])
        return db_mock
    def replicate(*args, **kwargs): pass
    def delete_db(*args): pass


class CouchdbManager(PersistenceManager):
    """ This is a couchdb manager for the workspace, it will load from the 
    couchdb databases"""
    def __init__(self, uri):
        self._last_seq_ack = 0
        getLogger(self).debug("Initializing CouchDBManager for url [%s]" % uri)
        self._lostConnection = False
        self.__uri = uri
        self.__dbs = {} 
        self.__seq_nums = {}
        self.__serv = NoConectionServer()
        self.mutex = threading.Lock()
        self._available = False
        try:
            self.testCouchUrl(uri)
            url=urlparse(uri)
            getLogger(self).debug("Setting user,pass %s %s" % (url.username, url.password))
            self.__serv = Server(uri = uri)
            #print dir(self.__serv)
            self.__serv.resource_class.credentials = (url.username, url.password)
            self._available = True
        except:
            getLogger(self).warn("No route to couchdb server on: %s" % uri)
            getLogger(self).debug(traceback.format_exc())

    def isAvailable(self):
        return self._available

    def lostConnectionResolv(self): 
        self._lostConnection = True
        self.__dbs.clear()
        self.__serv = NoConectionServer()

    def reconnect(self):
        ret_val = False
        ur = self.__uri
        if CouchdbManager.testCouch(ur):
            self.__serv = Server(uri = ur)
            self.__dbs.clear()
            self._lostConnection = False
            ret_val = True

        return ret_val



    @staticmethod
    def testCouch(uri):
        host, port = None, None
        try:
            import socket
            url=urlparse(uri)
            proto = url.scheme
            host=url.hostname
            port=url.port

            port = port if port else socket.getservbyname(proto)
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, int(port)))
        except:
            return False
        getLogger(CouchdbManager).info("Connecting Couch to: %s:%s" % (host, port))
        return True



    def testCouchUrl(self, uri):
        url=urlparse(uri)
        proto = url.scheme
        host=url.hostname
        port=url.port        
        self.test(host, int(port))

    def test(self, address, port):
        import socket
        s = socket.socket()
        s.settimeout(1)
        s.connect((address, port))


    @trap_timeout
    def getWorkspacesNames(self):
        return filter(lambda x: not x.startswith("_"), self.__serv.all_dbs())

    def workspaceExists(self, name):
        return name in self.getWorkspacesNames()


    @trap_timeout
    def addWorkspace(self, aWorkspace):
        self.__serv.create_db(aWorkspace.lower())
        return self.__getDb(aWorkspace)

    @trap_timeout
    def addDocument(self, aWorkspaceName, documentId, aDocument):
        self.__getDb(aWorkspaceName)
        self.incrementSeqNumber(aWorkspaceName)
        self.__getDb(aWorkspaceName)[documentId] = aDocument

    @trap_timeout
    def saveDocument(self, aWorkspaceName, aDocument):
        self.incrementSeqNumber(aWorkspaceName)
        getLogger(self).debug("Saving document in remote workspace %s" % aWorkspaceName)
        return self.__getDb(aWorkspaceName).save_doc(aDocument, use_uuids = True, force_update = True)

    @trap_timeout
    def __getDb(self, aWorkspaceName): 
        aWorkspaceName = aWorkspaceName.lower()
        getLogger(self).debug("Getting workspace [%s]" % aWorkspaceName)
        workspacedb = self.__dbs.get(aWorkspaceName, self.__serv.get_db(aWorkspaceName))
        if not self.__dbs.has_key(aWorkspaceName): 
            getLogger(self).debug("Asking couchdb for workspace [%s]" % aWorkspaceName)
            self.__dbs[aWorkspaceName] = workspacedb
            self.__seq_nums[aWorkspaceName] = workspacedb.info()['update_seq'] 


        return workspacedb

    @trap_timeout
    def getDocument(self, aWorkspaceName, documentId):
        getLogger(self).debug("Getting document for workspace [%s]" % aWorkspaceName)
        return self.__getDb(aWorkspaceName).get(documentId)

    @trap_timeout
    def checkDocument(self, aWorkspaceName, documentName):
        return  self.__getDb(aWorkspaceName).doc_exist(documentName)


    @trap_timeout
    def replicate(self, workspace, *targets_dbs, **kwargs):
        getLogger(self).debug("Targets to replicate %s" % str(targets_dbs))
        for target_db in targets_dbs:
            src_db_path = "/".join([self.__uri, workspace])
            dst_db_path = "/".join([target_db, workspace])
            try:
                getLogger(self).info("workspace: %s, src_db_path: %s, dst_db_path: %s, **kwargs: %s" % (workspace, src_db_path, dst_db_path, kwargs))
                self.__peerReplication(workspace, src_db_path, dst_db_path, **kwargs)
            except ResourceNotFound as e:
                raise e
            except Exception as e:
                getLogger(self).error(e)
                raise 

    def __peerReplication(self, workspace, src, dst, **kwargs):
        mutual = kwargs.get("mutual", True)
        continuous = kwargs.get("continuous", True)
        ct = kwargs.get("create_target", True)

        self.__serv.replicate(workspace, dst, mutual = mutual, continuous  = continuous, create_target = ct)
        if mutual:
            self.__serv.replicate(dst, src, continuous = continuous, **kwargs)


    def getLastChangeSeq(self, workspaceName):
        self.mutex.acquire()
        seq = self.__seq_nums[workspaceName]
        self.mutex.release()
        return seq

    def setLastChangeSeq(self, workspaceName, seq_num):
        self.mutex.acquire()
        self.__seq_nums[workspaceName] = seq_num
        self.mutex.release()


    @trap_timeout
    def waitForDBChange(self, db_name, since = 0, timeout = 15000):
        """ Be warned this will return after the database has a change, if
        there was one before call it will return immediatly with the changes
        done"""
        changes = []
        last_seq = max(self.getLastChangeSeq(db_name), since)
        db = self.__getDb(db_name)
        with ChangesStream(db, feed="longpoll", since = last_seq, timeout = timeout) as stream:
            for change in stream:
                if change['seq'] > self.getLastChangeSeq(db_name):
                    changes.append(change)
            last_seq = reduce(lambda x,y:  max(y['seq'], x) , changes, self.getLastChangeSeq(db_name))
            self.setLastChangeSeq(db_name, last_seq)
        return changes

    @trap_timeout
    def delete_all_dbs(self):
        for db in self.__serv.all_dbs():
            self.__serv.delete_db(db)

    @trap_timeout
    def existWorkspace(self, name):
        return name in self.__serv.all_dbs()

    @trap_timeout
    def workspaceDocumentsIterator(self, workspaceName): 
        return filter(self.filterConditions, self.__getDb(workspaceName).documents(include_docs=True))

    def filterConditions(self, doc):
        model_object_types = [c.__name__ for c in ModelObject.__subclasses__()]
        ret = True
        ret = ret and not doc["id"].startswith("_")
        ret = ret and doc['doc']["type"] in model_object_types

        return ret

    @trap_timeout
    def removeWorkspace(self, workspace_name):
        return self.__serv.delete_db(workspace_name)

    @trap_timeout
    def remove(self, workspace, host_id):
        self.incrementSeqNumber(workspace)
        self.__dbs[workspace].delete_doc(host_id)

    @trap_timeout
    def compactDatabase(self, aWorkspaceName):
        self.__getDb(aWorkspaceName).compact()

    def pushReports(self):
        vmanager = ViewsManager()
        reports = os.path.join(os.getcwd(), "views", "reports")
        workspace = self.__serv.get_or_create_db("reports") 
        vmanager.addView(reports, workspace)
        return self.__uri + "/reports/_design/reports/index.html"


    def addViews(self, workspaceName):
        vmanager = ViewsManager()
        workspace = self.__getDb(workspaceName)
        for v in vmanager.getAvailableViews():
            vmanager.addView(v, workspace)

    def getViews(self, workspaceName):
        vmanager = ViewsManager()
        workspace = self.__getDb(workspaceName)
        return vmanager.getViews(workspace)

    def syncWorkspaceViews(self, workspaceName):
        vmanager = ViewsManager()
        workspace = self.__getDb(workspaceName) 
        installed_views = vmanager.getViews(workspace)
        for v in vmanager.getAvailableViews():
            if v not in installed_views: 
                vmanager.addView(v, workspace)

    def incrementSeqNumber(self, workspaceName):
        self.mutex.acquire()
        if not self.__seq_nums.has_key(workspaceName):
            self.__seq_nums[workspaceName] = 0
        self.__seq_nums[workspaceName] += 1 
        self.mutex.release()

class ViewsManager(object):
    """docstring for ViewsWrapper"""
                           
                                        
    def __init__(self):
        self.vw = ViewsListObject()

             
    def addView(self, design_doc, workspaceDB):
        designer.push(design_doc, workspaceDB, atomic = False)

    def addViewForFS(self, design_doc, workspaceDB):
        designer.fs.push(design_doc, workspaceDB, encode_attachments = False)


    def getAvailableViews(self):
        return self.vw.get_all_views()

    def getViews(self, workspaceDB):
        views = {}
        result = workspaceDB.all_docs(startkey='_design', endkey='_design0')
        if result:
            for doc in result.all():
                designdoc = workspaceDB.get(doc['id'])
                views.update(designdoc.get("views", []))
        return views

class ViewsListObject(object):
    """ Representation of the FS Views """
    def __init__(self):
        self.views_path = os.path.join(os.getcwd(), "views")
        self.designs_path = os.path.join(self.views_path, "_design") 

    def _listPath(self, path):
        flist = filter(lambda x: not x.startswith('.'), os.listdir(path))
        return map(lambda x: os.path.join(path, x), flist)

    def get_fs_designs(self):
        return self._listPath(self.designs_path)

    def get_all_views(self):
        return self.get_fs_designs()

class PluginManager(object):
    def __init__(self, plugin_repo_path):
        self._controllers = {}                                         
        self._plugin_modules = {}                                        
        self._loadPlugins(plugin_repo_path)

        self._plugin_settings = {}
        self._loadSettings()

    def createController(self, id):
        """
        Creates a new plugin controller and adds it into the controllers list.
        """
        plugs = self._instancePlugins()
        new_controller = plugins.core.PluginController(id, plugs, CommandManager())
        self._controllers[new_controller.id] = new_controller
        return new_controller

    def _loadSettings(self):
        _plugin_settings=CONF.getPluginSettings()
        if _plugin_settings:
                                          
            self._plugin_settings=_plugin_settings
        
        activep=self._instancePlugins()
        for plugin_id, plugin in activep.iteritems():
                                            
            if not plugin_id in _plugin_settings:
                self._plugin_settings[plugin_id] = {
                                        "name": plugin.name,
                                        "description": plugin.description,
                                        "version": plugin.version,
                                        "plugin_version": plugin.plugin_version,
                                        "settings": dict(plugin.getSettings())
                                                  }
                                           
        dplugins=[]
        for k,v in self._plugin_settings.iteritems():
            if not k in activep:
                dplugins.append(k)
        
        for d in dplugins:
            del self._plugin_settings[d]
        
                           
        CONF.setPluginSettings(self._plugin_settings)
        CONF.saveConfig()

    def getSettings(self):
        return self._plugin_settings

    def updateSettings(self, settings):
        self._plugin_settings = settings
        CONF.setPluginSettings(settings)
        CONF.saveConfig()
        for plugin_id, params in settings.iteritems():
            new_settings = params["settings"]
            for c_id, c_instance in self._controllers.iteritems():
                c_instance.updatePluginSettings(plugin_id, new_settings)

    def _instancePlugins(self):
        plugins = {}
        for module in self._plugin_modules.itervalues():
            new_plugin = module.createPlugin()
            self._verifyPlugin(new_plugin)
            plugins[new_plugin.id] = new_plugin
        return plugins

    def _loadPlugins(self, plugin_repo_path):
        """
        Finds and load all the plugins that are available in the plugin_repo_path.
        """
        try:
            os.stat(plugin_repo_path)
        except OSError:
                                 
            pass
        
        sys.path.append(plugin_repo_path)

        dir_name_regexp = re.compile(r"^[\d\w\-\_]+$")
        for name in os.listdir(plugin_repo_path):
            if dir_name_regexp.match(name):
                try:
                    module_path = os.path.join(plugin_repo_path, name)
                    sys.path.append(module_path)
                    module_filename = os.path.join(module_path, "plugin.py")
                    self._plugin_modules[name] = imp.load_source(name, module_filename)
                except Exception:
                    msg = "An error ocurred while loading plugin %s.\n%s" % (module_filename, traceback.format_exc())
                    getLogger(self).error(msg)
            else:
                pass

    def getPlugins(self):
        return self._instancePlugins()
                                                 

    def _updatePluginSettings(self, new_plugin_id):
        pass

    def _verifyPlugin(self, new_plugin):
        """ Generic method that decides is a plugin is valid
            based on a predefined set of checks. """
        try:
            assert(new_plugin.id is not None)
            assert(new_plugin.version is not None)
            assert(new_plugin.name is not None)
            assert(new_plugin.framework_version is not None)
        except (AssertionError,KeyError):
                                           
            return False
        return True
