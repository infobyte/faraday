# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from utils.logs import getLogger
from model.workspace import Workspace
from persistence.persistence_managers import DBTYPE

class WorkspaceManager(object):
    """Workspace Manager class
    It's responsabilities goes from:
        * Workspace creation
        * Workspace removal
        * Workspace opening
        * Active Workspace switching"""

    def __init__(self, dbManager, mappersManager, changesManager,*args, **kwargs):
        self.dbManager = dbManager
        self.mappersManager = mappersManager
        self.changesManager = changesManager

    def createWorkspace(self, name, desc, dbtype):
        workspace = Workspace(name, desc)
        dbConnector = self.dbManager.createDb(name, dbtype)
        if dbConnector:
            self.mappersManager.createMappers(dbConnector)
            dbConnector.setChangesCallback(self.changesManager)
            self.mappersManager.saveObj(workspace)
            return workspace
        return False

    def openWorkspace(self, name):
        dbConnector = self.dbManager.dbOpen(name)
        if dbConnector:
            dbConnector.setChangesCallback(self.changesManager)
            self.mappersManager.createMappers(dbConnector)
            workspace = self.mappersManager.find(name)
            return workspace
        return False

    def removeWorkspace(self, name):
        return self.dbManager.removeDb(name)

    def setActiveWorkspace(self, workspace):
        self.active_workspace = workspace

    def isActive(self, name):
        return self.active_workspace.getName() == name

    def getWorkspaceType(self, name): 
        if self.dbManager.getDbType(name) == DBTYPE.COUCHDB:
            return 'CouchDB'
        if self.dbManager.getDbType(name) == DBTYPE.FS:
            return 'FS' 

