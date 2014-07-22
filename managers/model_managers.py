# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from utils.logs import getLogger
from model.workspace import Workspace

class WorkspaceManager(object):
    """Workspace Manager class
    It's responsabilities goes from:
        * Workspace creation
        * Workspace removal
        * Workspace opening
        * Active Workspace switching"""

    def __init__(self, dbManager, mappersManager, *args, **kwargs):
        self.dbManager = dbManager
        self.mappersManager = mappersManager

    def createWorkspace(self, name, desc, dbtype):
        workspace = Workspace(name, desc)
        dbConnector = self.dbManager.createDb(name, dbtype)
        if dbConnector:
            self.mappersManager.createMappers(dbConnector)
            self.mappersManager.saveObj(workspace)
            return workspace
        return False

    def openWorkspace(self, name):
        dbConnector = self.dbManager.dbOpen(name)
        if dbConnector:
            self.mappersManager.createMappers(dbConnector)
            workspace = self.mappersManager.findObject(name)
            return workspace
        return False

    def removeWorkspace(self, name):
        pass


