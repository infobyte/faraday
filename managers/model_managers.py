# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from utils.logs import getLogger
from model.workspace import Workspace
from persistence.persistence_managers import DBTYPE

from model.guiapi import notification_center

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class WorkspaceManager(object):
    """Workspace Manager class
    It's responsabilities goes from:
        * Workspace creation
        * Workspace removal
        * Workspace opening
        * Active Workspace switching"""

    def __init__(self, dbManager, mappersManager, changesManager, reportsManager, *args, **kwargs):
        self.dbManager = dbManager
        self.mappersManager = mappersManager
        self.changesManager = changesManager
        self.reportsManager = reportsManager
        self.active_workspace = None

    def getWorkspacesNames(self):
        return self.dbManager.getAllDbNames()

    def createWorkspace(self, name, desc, dbtype=DBTYPE.FS):
        workspace = Workspace(name, desc)
        dbConnector = self.dbManager.createDb(name, dbtype)
        if dbConnector:
            self.closeWorkspace()
            self.mappersManager.createMappers(dbConnector)
            self.mappersManager.save(workspace)
            self.setActiveWorkspace(workspace)
            notification_center.workspaceChanged(workspace)
            notification_center.workspaceLoad(workspace.getHosts())
            self.changesManager.watch(self.mappersManager, dbConnector)
            self.reportsManager.watch(name)
            return workspace
        return False

    def openWorkspace(self, name):
        if name in self.getWorkspacesNames():
            self.closeWorkspace()
            dbConnector = self.dbManager.getConnector(name)
            self.mappersManager.createMappers(dbConnector)
            workspace = self.mappersManager.getMapper(Workspace.__name__).find(name)
            self.setActiveWorkspace(workspace)
            CONF.setLastWorkspace(name)
            CONF.saveConfig()
            notification_center.workspaceChanged(workspace)
            notification_center.workspaceLoad(workspace.getHosts())
            self.changesManager.watch(self.mappersManager, dbConnector)
            self.reportsManager.watch(name)
            return workspace
        return None

    def closeWorkspace(self):
        self.changesManager.unwatch()


    def removeWorkspace(self, name):
        if name in self.getWorkspacesNames():
            return self.dbManager.removeDb(name)

    def setActiveWorkspace(self, workspace):
        self.active_workspace = workspace

    def getActiveWorkspace(self):
        return self.active_workspace

    def workspaceExists(self, name):
        return self.dbManager.connectorExists(name)

    def resource(self):
        self.dbManager.reloadConfig()

    def isActive(self, name):
        return self.active_workspace.getName() == name

    def getWorkspaceType(self, name):
        return self._dbTypeToNamedType(self.dbManager.getDbType(name))

    def _dbTypeToNamedType(self, dbtype):
        if dbtype == DBTYPE.COUCHDB:
            return 'CouchDB'
        if dbtype == DBTYPE.FS:
            return 'FS'

    def namedTypeToDbType(self, name):
        if name =='CouchDB':
            return DBTYPE.COUCHDB
        if name == 'FS':
            return DBTYPE.FS

    def getAvailableWorkspaceTypes(self):
        return [self._dbTypeToNamedType(dbtype) for \
                dbtype in self.dbManager.getAvailableDBs()]

