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
from model.report import ReportManager
from model.guiapi import notification_center as notifier

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

import shutil
from managers.all import PersistenceManagerFactory, FSManager


class Workspace(object):
    """
    Handles a complete workspace (or project)
    It contains a reference to the model and the command execution
    history for all users working on the same workspace.
    It has a list with all existing workspaces just in case user wants to
    open a new one.
    """

    def __init__(self, name, desc=None, manager=None, shared=CONF.getAutoShareWorkspace()):
        self.name = name
        self.description = ""
        self.customer = ""
        self.start_date = time.time()
        self.finish_date = time.time()
        self._id = name
        self._command_history = None
        self.shared = shared
        self.hosts = {}

        self._report_path = os.path.join(CONF.getReportPath(), name)
        self._report_ppath = os.path.join(self._report_path, "process")

        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)

        if not os.path.exists(self._report_ppath):
            os.mkdir(self._report_ppath)

    def getID(self):
        return self._id

    def setID(self, id):
        self._id = id

    def getName(self):
        return self.name

    def setName(self, name):
        self.name = name

    def getDescription(self):
        return self.description

    def setDescription(self, desc):
        self.description = desc

    def getCustomer(self):
        return self.customer

    def setCustomer(self, customer):
        self.customer = customer

    def getStartDate(self):
        return self.start_date

    def setStartDate(self, sdate):
        self.start_date = sdate

    def getFinishDate(self):
        return self.finish_date

    def setFinishDate(self, fdate):
        self.finish_date = fdate

    def _notifyWorkspaceNoConnection(self):
        notifier.showPopup("Couchdb Connection lost. Defaulting to memory. Fix network and try again in 5 minutes.")

    def getReportPath(self):
        return self._report_path

    def set_path(self, path):
        self._path = path

    def get_path(self):
        return self._path

    def set_report_path(self, path):
        self._report_path = path
        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)
        #self._workspace_manager.report_manager.path = self.report_path

    def get_report_path(self):
        return self._report_path

    path = property(get_path, set_path) 
    report_path = property(get_report_path, set_report_path)

    def isActive(self):
        return self.name == self._workspace_manager.getActiveWorkspace().name

    def getHosts(self):
        return self.hosts.values()

    def setHosts(self, hosts):
        self.hosts = hosts

    def getDeletedHosts(self):
        return self._model_controller.getDeletedHosts()

    def cleanDeletedHosts(self):
        self._model_controller.cleanDeletedHosts()


class WorkspaceManager(object):
    """
    This handles all workspaces. It checks for existing workspaces inside
    the persistence directory.
    It is in charge of starting the WorkspacesAutoSaver to persist each workspace.
    This class stores information in $HOME/.faraday/config/workspacemanager.xml file
    to keep track of created workspaces to be able to load them
    """
    # REFACTOR
    def __init__(self, model_controller, plugin_controller):
        self.active_workspace = None
                                                                  
        self._couchAvailable  = False 
        self.report_manager = ReportManager(10, plugin_controller)
        
        self.couchdbmanager = PersistenceManagerFactory().getInstance()
        self.fsmanager = FSManager()
        
        self._workspaces = {}
        self._workspaces_types = {}
        self._model_controller = model_controller
        self._excluded_directories = [".svn"]
        self.workspace_persister = WorkspacePersister()

    def couchAvailable(self, isit):
        self._couchAvailable = isit

    def _notifyWorkspaceNoConnection(self):
        notifier.showPopup("Couchdb Connection lost. Defaulting to memory. Fix network and try again in 5 minutes.")

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

    def createWorkspace(self, name, description="", workspaceClass = None, shared=CONF.getAutoShareWorkspace(),
                        customer="", sdate=None, fdate=None):

        model.api.devlog("Creating Workspace")
        if self.getWorkspaceType(name) in globals():
            workspaceClass = globals()[self.getWorkspaceType(name)]
        elif not workspaceClass:
            # Defaulting =( 
            model.api.devlog("Defaulting to WorkspaceOnFS") 
            workspaceClass = WorkspaceOnFS

        w = workspaceClass(name, self, shared)
        # Register the created workspace type:
        self._workspaces_types[name] = workspaceClass.__name__
        w.description = description
        w.customer = customer
        if sdate is not None:
            w.start_date = sdate
        if fdate is not None:
            w.finish_date = fdate
        self.addWorkspace(w)
        return w

    def removeWorkspace(self, name):
        work = self.getWorkspace(name)
        if not work: return
        dm = work.getDataManager()
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
        if not self._workspaces.get(name):
            # Retrieve the workspace
            self.loadWorkspace(name) 
        return  self._workspaces.get(name)

    def loadWorkspace(self, name): 
        workspaceClass = None
        workspace = None
        if name in self.fsmanager.getWorkspacesNames():
            workspace = self.createWorkspace(name, workspaceClass = WorkspaceOnFS) 
        elif name in self.couchdbmanager.getWorkspacesNames():
            workspace = self.createWorkspace(name, workspaceClass = WorkspaceOnCouch)

        return workspace

    def openWorkspace(self, name):
        w = self.getWorkspace(name)
        self.setActiveWorkspace(w)
        return w
        
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

        self._workspaces_types = {}
        fsworkspaces = {name: None for name in self.fsmanager.getWorkspacesNames()}
        self._workspaces.update(fsworkspaces)
        couchworkspaces = {name: None for name in self.couchdbmanager .getWorkspacesNames()
                                                if not name == 'reports'}
        self._workspaces.update(couchworkspaces)

        self._workspaces_types.update({name: WorkspaceOnFS.__name__  for name in fsworkspaces})
        self._workspaces_types.update({name: WorkspaceOnCouch.__name__  for name in couchworkspaces})

    def getWorkspaceType(self, name):
        return self._workspaces_types.get(name, 'undefined')
 
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

    def isActive(self, name):
        return self.active_workspace.name == name
                
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

