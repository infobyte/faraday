#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import model.api
import model
import threading
import time
import datetime
import traceback
from persistence.common import DataManager
from model.report import ReportManager
from model.diff import HostDiff
from model.container import ModelObjectContainer, CouchedModelObjectContainer
from model.conflict import Conflict
from model.hosts import Host
import model.guiapi as guiapi
from gui.qt3.customevents import ShowPopupCustomEvent

from couchdbkit import Server, ChangesStream, Database, designer
from couchdbkit.resource import ResourceNotFound

import mockito
import traceback

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

from urlparse import urlparse
import json
import shutil

from persistence.orm import WorkspacePersister
from utils.decorators import trap_timeout

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

    def notifyWorkspaceNoConnection(self): 
        self._model_controller._notifyWorkspaceConnectionLost() 

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
        model.api.devlog("Changes from another instance")
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
            self._model_controller._notifyModelUpdated()



                                                                                

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
        model.api.log("Initializing CouchDBManager for url [%s]" % uri)
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
            print ("Setting user,pass %s %s" % (url.username, url.password))
            self.__serv = Server(uri = uri)
            #print dir(self.__serv)
            self.__serv.resource_class.credentials = (url.username, url.password)
            self._available = True
        except:
            model.api.log("No route to couchdb server on: %s" % uri)
            print(traceback.format_exc())

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
        model.api.log("Connecting Couch to: %s:%s" % (host, port))
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
        self.incrementSeqNumber(aWorkspaceName)
        self.__getDb(aWorkspaceName)[documentId] = aDocument

    @trap_timeout
    def saveDocument(self, aWorkspaceName, aDocument):
        self.incrementSeqNumber(aWorkspaceName)
        model.api.log("Saving document in remote workspace %s" % aWorkspaceName)
        self.__getDb(aWorkspaceName).save_doc(aDocument, use_uuids = True, force_update = True)

    @trap_timeout
    def __getDb(self, aWorkspaceName): 
        aWorkspaceName = aWorkspaceName.lower()
        model.api.log("Getting workspace [%s]" % aWorkspaceName)
        workspacedb = self.__dbs.get(aWorkspaceName, self.__serv.get_db(aWorkspaceName))
        if not self.__dbs.has_key(aWorkspaceName): 
            model.api.log("Asking couchdb for workspace [%s]" % aWorkspaceName)
            self.__dbs[aWorkspaceName] = workspacedb
            self.__seq_nums[aWorkspaceName] = workspacedb.info()['update_seq'] 
        return workspacedb

    @trap_timeout
    def getDocument(self, aWorkspaceName, documentId):
        model.api.log("Getting document for workspace [%s]" % aWorkspaceName)
        return self.__getDb(aWorkspaceName).get(documentId)

    @trap_timeout
    def checkDocument(self, aWorkspaceName, documentName):
        return  self.__getDb(aWorkspaceName).doc_exist(documentName)


    @trap_timeout
    def replicate(self, workspace, *targets_dbs, **kwargs):
        model.api.log("Targets to replicate %s" % str(targets_dbs))
        for target_db in targets_dbs:
            src_db_path = "/".join([self.__uri, workspace])
            dst_db_path = "/".join([target_db, workspace])
            try:
                model.api.devlog("workspace: %s, src_db_path: %s, dst_db_path: %s, **kwargs: %s" % (workspace, src_db_path, dst_db_path, kwargs))
                self.__peerReplication(workspace, src_db_path, dst_db_path, **kwargs)
            except ResourceNotFound as e:
                raise e
            except Exception as e:
                model.api.devlog(e)
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
        return filter(lambda x: not x["id"].startswith("_"), self.__getDb(workspaceName).documents(include_docs=True))

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
        self.__seq_nums[workspaceName] += 1 
        self.mutex.release()


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
        
        self.couchdbmanager = CouchdbManager(uri = CONF.getCouchURI())
        
        self._workspaces = {}
        self._model_controller = model_controller
        self._excluded_directories = [".svn"]                             
        self.workspace_persister = WorkspacePersister()

    def couchAvailable(self, isit):
        self._couchAvailable = isit

    def reconnect(self):
        if not self.reconnectCouchManager():
            self._model_controller._notifyWorkspaceConnectionLost()

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
        guiapi.postCustomEvent((ShowPopupCustomEvent("No visualizations available, please install and configure CouchDB")))
    
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
                                                                
                                         
                                                                              
                                                                        
                                                                                          
                                                                                   
                                                                            
        self._workspaces.clear()
        for name in os.listdir(CONF.getPersistencePath()):
            if name not in self._workspaces:
                if os.path.isdir(os.path.join(CONF.getPersistencePath(),name)) and name not in self._excluded_directories:
                    w = self.createWorkspace(name, workspaceClass = WorkspaceOnFS)

        for name in self.couchdbmanager.getWorkspacesNames():
            if name not in self._workspaces and not name == "reports":
                self.createWorkspace(name, workspaceClass = WorkspaceOnCouch)
    
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

