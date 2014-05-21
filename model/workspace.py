#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import model.api
import model
import time
import datetime
from model.report import ReportManager
from model.diff import HostDiff
from model.container import ModelObjectContainer, CouchedModelObjectContainer
from model.conflict import Conflict
from model.hosts import Host
from model.guiapi import notification_center as notifier


import mockito

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

import json
import shutil

from persistence.orm import WorkspacePersister

from managers.all import PersistenceManagerFactory, CouchdbManager, FSManager

class Workspace(object):
    """
    Handles a complete workspace (or project)
    It contains a reference to the model and the command execution
    history for all users working on the same workspace.
    It has a list with all existing workspaces just in case user wants to
    open a new one.
    """
                                                                    
                                             
                                                          
                                                               
                                                                                 
    
    def __init__(self, name, manager, shared=CONF.getAutoShareWorkspace()):
        self.name                   = name
        self.description            = ""
        self.customer               = ""
        self.start_date             = datetime.date(1,1,1)
        self.finish_date            = datetime.date(1,1,1)
        self.id                     = name                                                              
        self._command_history       = None
        self._model_controller      = None
        self._workspace_manager     = manager
        self.shared                 = shared                                      

        self._path                  = os.path.join(CONF.getPersistencePath(), name)
        self._persistence_excluded_filenames = ["categories.xml", "workspace.xml"]


        self.container = ModelObjectContainer()
        self.__conflicts            = []

        self._object_factory = model.common.factory
        self._object_factory.register(model.hosts.Host)
        
        self._report_path = os.path.join(CONF.getReportPath(), name)
        self._report_ppath = os.path.join(self._report_path,"process")
        
        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)
         
        if not os.path.exists(self._report_ppath):
            os.mkdir(self._report_ppath)

    def _notifyWorkspaceNoConnection(self):
        notifier.showPopup("Couchdb Connection lost. Defaulting to memory. Fix network and try again in 5 minutes.")

    def getReportPath(self):
        return self._report_path

    def saveObj(obj):raise NotImplementedError("Abstract method")
    def delObj(obj):raise NotImplementedError("Abstract method")

    def remove(self, host):
        del self.container[host.getID()]
        self.delObj(host)

    def save(self): raise NotImplementedError("Abstract method")
    def load(self): raise NotImplementedError("Abstract method")

        
    def setModelController(self, model_controller):
        self._model_controller = model_controller

    def getContainee(self):
        return self.container


    def set_path(self, path):
        self._path = path
    
    def get_path(self):
        return self._path
    

    def set_report_path(self, path):
        self._report_path = path
        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)
        self._workspace_manager.report_manager.path = self.report_path

    def get_report_path(self):
        return self._report_path
    
    path = property(get_path, set_path) 
    report_path = property(get_report_path, set_report_path)
    
                              
            
                                                           
                                     
            
             
     
                                    
            
                                                           
            
             
    
    def isActive(self):
        return self.name == self._workspace_manager.getActiveWorkspace().name

    def getAllHosts(self):
        return self._model_controller.getAllHosts()

    def getDeletedHosts(self):
        return self._model_controller.getDeletedHosts()
    
    def cleanDeletedHosts(self):
        self._model_controller.cleanDeletedHosts()

    def verifyConsistency(self):
                                                        
        hosts = self.getAllHosts()
        hosts_counter = 0
        for h1 in hosts[:-1]:
            hosts_counter += 1
            for h2 in hosts[hosts_counter:]:
                if h1 == h2 :
                    diff = HostDiff(h1, h2)
                    if diff.existDiff():
                        self.addConflict(Conflict(h1, h2))
                                           
                                                                     
        return len(self.getConflicts())


    def getDataManager(self):
        return self._dmanager

    def addConflict(self, conflict):
        self.__conflicts.append(conflict)

    def getConflicts(self):
        return self.__conflicts

    def clearConflicts(self):
        self.__conflicts.clear()

    def resolveConflicts(self):
        pass

    def conflictResolved(self, conflict):
        self.__conflicts.remove(conflict)

class WorkspaceOnFS(Workspace):

    def __init__(self, name, manager, shared=CONF.getAutoShareWorkspace()):
        Workspace.__init__(self, name, manager, shared) 
        self._dmanager = FSManager(self._path)

    @staticmethod
    def isAvailable():
        return True

    def saveObj(self, obj):
        host = obj.getHost()
        try: 
            model.api.devlog("Saving host to FileSystem")
            model.api.devlog("Host, %s" % host.getID())
            host_as_dict = host._toDict(full=True)
            filepath = os.path.join(self._path, host.getID() + ".json")
            with open(filepath, "w") as outfile:
                json.dump(host_as_dict, outfile, indent = 2) 
        except Exception:
            model.api.devlog("Failed while persisting workspace to filesystem, enough perms and space?")

    def delObj(self, obj):
        if obj.class_signature == "Host":
            self._dmanager.removeObject(obj.getID())
            return
        host = obj.getHost()
        self.saveObj(host)

    def syncFiles(self):
        self.load()

    def load(self):
                                                       
        files = os.listdir(self._path)
        files = filter(lambda f: f.endswith(".json") and f not in
                self._persistence_excluded_filenames, files)
        modelobjectcontainer = self.getContainee()
        for filename in files:
            newHost = self.__loadHostFromFile(filename)
            modelobjectcontainer[newHost.getID()] = newHost

    def __loadHostFromFile(self, filename):
        if os.path.basename(filename) in self._persistence_excluded_filenames:
            model.api.devlog("skipping file %s" % filename)
            return
        else:
            model.api.devlog("loading file %s" % filename)
            
        infilepath = os.path.join(self._path, filename)
        host_dict = {}
        try:
            with open(infilepath) as infile: 
                host_dict = json.load(infile) 
        except Exception, e:
            model.api.log("An error ocurred while parsing file %s\n%s" %
                     (filename, str(e)), "ERROR")
            return mockito.mock()
        
                                                                       
                                                                     
        try:
            newHost = Host(name=None, dic=host_dict)
                                        
            return newHost
        except Exception, e:
            model.api.log("Could not load host from file %s" % filename, "ERROR")
            model.api.devlog(str(e))
            return None


class WorkspaceOnCouch(Workspace):
    """A Workspace that is syncronized in couchdb"""
    def __init__(self, name, manager, *args):
        super(WorkspaceOnCouch, self).__init__(name, manager)
        self._is_replicated = replicated = CONF.getCouchIsReplicated()
        self.cdm  = self._dmanager = manager.couchdbmanager
            
        if not self.cdm.workspaceExists(name):
            self.cdm.addWorkspace(name)
            if self.is_replicated():
                self.cdm.replicate(self.name, *self.validate_replic_urls(CONF.getCouchReplics()), create_target = True)

        self.cdm.syncWorkspaceViews(name)

        self.container = CouchedModelObjectContainer(name, self.cdm)
       

    def syncFiles(self):
        self.load()

    @staticmethod
    def isAvailable():
        return CouchdbManager.testCouch(CONF.getCouchURI())

    def is_replicated(self):
        return self._is_replicated

    def validate_replic_urls(self, urlsString):
                                      
        urls = urlsString.split(";") if urlsString is not None else ""
                                                            
        valid_replics = []
        for url in urls:
            try:
                self.cdm.testCouchUrl(url)
                valid_replics.append(url)
            except:
                pass

        return valid_replics

    def saveObj(self, obj):
        self.cdm.saveDocument(self.name, obj._toDict())
        self.cdm.compactDatabase(self.name)

    def delObj(self, obj):
        obj_id = obj.ancestors_path()
        if self._dmanager.checkDocument(self.name, obj_id):
            self._dmanager.remove(self.name, obj_id)
  
    def save(self): 
        model.api.devlog("Saving workspaces")
        for host in self.getContainee().itervalues():
            host_as_dict = host.toDict()
            for obj_dic in host_as_dict:
                self.cdm.saveDocument(self.name, obj_dic)
                                            

    def load(self):
        self._model_controller.setSavingModel(True)
        hosts = {}

        def find_leaf(path, sub_graph = hosts):
            for i in path:
                if len(path) > 1:
                    return find_leaf(path[1:], sub_graph['subs'][i])
                else:
                    return sub_graph
        try:
            t = time.time()
            model.api.devlog("load start: %s" % str(t))
            docs = [i["doc"] for i in self.cdm.workspaceDocumentsIterator(self.name)]
            model.api.devlog("time to get docs: %s" % str(time.time() - t))
            t = time.time()
            for d in docs:
                id_path = d['_id'].split('.')
                if d['type'] == "Host":
                    hosts[d['_id']] = d
                    subs = hosts.get('subs', {})
                    subs[d['_id']] = d
                    hosts['subs'] = subs
                    continue

                leaf = find_leaf(id_path)
                subs = leaf.get('subs', {})
                subs[d['obj_id']] = d
                leaf['subs'] = subs

                key = "%s" % d['type']
                key = key.lower()
                sub = leaf.get(key, {})
                sub[d['obj_id']] = d
                leaf[key] = sub
            model.api.devlog("time to reconstruct: %s" % str(time.time() - t))
            t = time.time()

            self.container.clear()
            for k, v in hosts.items():
                if k is not "subs":
                    h = Host(name=None, dic=v)
                    self.container[k] = h
            model.api.devlog("time to fill container: %s" % str(time.time() - t))
            t = time.time()
        except Exception, e:
            model.api.devlog("Exception during load: %s" % e)
        finally:
            self._model_controller.setSavingModel(False)
            notifier.workspaceLoad(self.getAllHosts())


class WorkspaceManager(object):
    """
    This handles all workspaces. It checks for existing workspaces inside
    the persistence directory.
    It is in charge of starting the WorkspacesAutoSaver to persist each workspace.
    This class stores information in $HOME/.faraday/config/workspacemanager.xml file
    to keep track of created workspaces to be able to load them
    """
    def __init__(self, model_controller, plugin_controller):
        self.active_workspace = None
                                                                  
        self._couchAvailable  = False 
        self.report_manager = ReportManager(10, plugin_controller)
        
        self.couchdbmanager = PersistenceManagerFactory().getInstance()
        
        self._workspaces = {}
        self._model_controller = model_controller
        self._excluded_directories = [".svn"]
        self.workspace_persister = WorkspacePersister()

    def couchAvailable(self, isit):
        self._couchAvailable = isit

    def reconnect(self):
        if not self.reconnectCouchManager():
            self._notifyWorkspaceNoConnection()

    def getCouchManager(self):
        return self.couchdbmanager

    def setCouchManager(self, cm):
        self.couchdbmanager = cm

    @staticmethod
    def getAvailableWorkspaceTypes(): 
        av = [w.__name__ for w in Workspace.__subclasses__() if w.isAvailable() ]
        model.api.devlog("Available wortkspaces: %s" ", ".join(av))
        return av
        
    def reconnectCouchManager(self):
        retval = True
        if not self.couchdbmanager.reconnect():
            retval = False
            return retval
        WorkspacePersister.reExecutePendingActions() 
        return retval
    
    def startAutoLoader(self): 
        pass

    def stopAutoLoader(self):
        pass
    

    def startReportManager(self):
        self.report_manager.start()
    
    def stopReportManager(self):
        self.report_manager.stop()
        self.report_manager.join()
        
    def getActiveWorkspace(self):
        return self.active_workspace
    
    def saveWorkspaces(self):
        pass
            
    def addWorkspace(self, workspace):
        self._workspaces[workspace.name] = workspace
 
    def createVisualizations(self):
        stat = False
        url = ""
        if self.couchdbmanager.isAvailable():
            stat = True
            url  = self.couchdbmanager.pushReports()
        else:
            self._notifyNoVisualizationAvailable()
        return stat, url

    def _notifyNoVisualizationAvailable(self):
        notifier.showPopup("No visualizations available, please install and configure CouchDB")

    def createWorkspace(self, name, description="", workspaceClass = WorkspaceOnFS, shared=CONF.getAutoShareWorkspace(),
                        customer="", sdate=None, fdate=None):
        if name not in self._workspaces:
            w = workspaceClass(name, self, shared)
            w.description = description
            w.customer = customer
            if sdate is not None:
                w.start_date = sdate
            if fdate is not None:
                w.finish_date = fdate
            self.addWorkspace(w)
        else:
            w = self._workspaces[name]
        return w

    def removeWorkspace(self, name):
        dm = self.getWorkspace(name).getDataManager()
        dm.removeWorkspace(name)
                       
        datapath = CONF.getDataPath()
        todelete = [i for i in os.listdir(datapath) if name in i ]
        for i in todelete:
            os.remove(os.path.join(datapath, i))

        shutil.rmtree(self.getWorkspace(name).getReportPath())
        del self._workspaces[name]
        if self.getWorkspace(name) == self.getActiveWorkspace() and self.getWorkspacesCount() > 0: 
            self.setActiveWorkspace(self.getWorkspace(self._workspaces.keys()[0]))

    def getWorkspace(self, name):
        ''' May return None '''
        return self._workspaces.get(name)
    
    def openWorkspace(self, name):
        if name in self._workspaces:
            w = self._workspaces[name]
            self.setActiveWorkspace(w)
            return w
        raise Exception("Error on OpenWorkspace for %s "  % name)
        
    def getWorkspaces(self):
        """
        Simply returns a list of all existing workspaces (including the active one)
        """
        self.loadWorkspaces()
        return [w for w in self._workspaces.itervalues()]
    
    def getWorkspacesCount(self):
        return len(self._workspaces)

    def getWorkspacesNames(self):
        return self._workspaces.keys()
        
    def loadWorkspaces(self): 
        # self._workspaces.clear()

        self._workspaces.update({name: None for name in os.listdir(CONF.getPersistencePath())})
        self._workspaces.update({name: None for name in self.couchdbmanager
                                                .getWorkspacesNames()
                                                if not name == 'reports'})
 
    def setActiveWorkspace(self, workspace):
        try:
            self.stopAutoLoader()
        except : pass

        if self.active_workspace is not None:
            self.active_workspace.setModelController(None)
        CONF.setLastWorkspace(workspace.name)
        CONF.saveConfig()
        self.active_workspace = workspace
        self.active_workspace.setModelController(self._model_controller)
        self._model_controller.setWorkspace(self.active_workspace)
        self.workspace_persister.setPersister(self.active_workspace, self.active_workspace._dmanager)

        self.report_manager.path = workspace.report_path

        if isinstance(self.active_workspace, WorkspaceOnCouch):
            self.startAutoLoader()
                
    def syncWorkspaces(self):
        """
        Synchronize persistence directory using the DataManager.
        We first make sure that all shared workspaces were added to the repo
        """
        pass

                                                                                
class NotSyncronizableWorkspaceException(Exception): pass
class ConflictsPendingToSolveException(Exception): pass

class WorkspaceSyncronizer(object):
    """Object whom purpose is to correctly syncronize a workspace
    Interacts with a DataManager and a Workspace Object as a mediator"""
    def __init__(self, workspace):
        self._workspace = workspace
        self._dmanager = workspace.getDataManager()

    def sync(self):
        if not self.localCheck():
            return False
                                  
        self._workspace.save()
        self._workspace.syncFiles()
        return True

    def localCheck(self):
        return True
                         
                                                                             
        if (self._workspace.verifyConsistency() > 0):
            if (len(self._workspace.resolveConflicts(local=True)) < 
                len(self._workspace.getConflicts())):
                                                                        
                return False
        return True

