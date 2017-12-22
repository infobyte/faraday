# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import restkit
import re
import time

from model.workspace import Workspace
from persistence.server.models import create_workspace, get_workspaces_names, get_workspace, delete_workspace
from persistence.server.server_io_exceptions import Unauthorized
from model.guiapi import notification_center

from config.configuration import getInstanceConfiguration
from config.globals import CONST_BLACKDBS
CONF = getInstanceConfiguration()


class WorkspaceException(Exception):
    pass


class WorkspaceManager(object):
    """
    This class is in charge of creating, deleting and opening workspaces
    """

    def __init__(self, mappersManager, *args, **kwargs):
        self.mappersManager = mappersManager
        self.active_workspace = None

    def getWorkspacesNames(self):
        """Returns the names of the workspaces as a list of strings"""
        return get_workspaces_names()

    def createWorkspace(self, name, desc, start_date=int(time.time() * 1000),
                        finish_date=int(time.time() * 1000), customer=""):
        # XXX: DEPRECATE NEXT LINE
        workspace = Workspace(name, desc)
        try:
            create_workspace(name, description=desc, start_date=start_date,
                             finish_date=finish_date, customer=customer)
        except Unauthorized:
            raise WorkspaceException(
                ("You're not authorized to create workspaces\n"
                 "Make sure you're an admin and add your credentials"
                 "to your user configuration "
                 "file in $HOME/.faraday/config/user.xml\n"
                 "For example: "
                 "<couch_uri>http://john:password@127.0.0.1:5984</couch_uri>"))
        except Exception as e:
            raise WorkspaceException(str(e))
        self.closeWorkspace()
        self.mappersManager.createMappers(name)
        self.setActiveWorkspace(workspace)
        notification_center.workspaceChanged(workspace)
        return name

    def openWorkspace(self, name):
        """Open a workspace by name. Returns the workspace. Raises an
        WorkspaceException if something went wrong along the way.
        """
        if name not in get_workspaces_names():
            raise WorkspaceException(
                "Workspace %s wasn't found" % name)
        self.closeWorkspace()
        try:
            workspace = get_workspace(name)
        except Unauthorized:
            raise WorkspaceException(
                ("You're not authorized to access this workspace\n"
                 "Add your credentials to your user configuration "
                 "file in $HOME/.faraday/config/user.xml\n"
                 "For example: "
                 "<couch_uri>http://john:password@127.0.0.1:5984</couch_uri>"))
        except Exception as e:
            notification_center.DBConnectionProblem(e)
            raise WorkspaceException(str(e))
        self.mappersManager.createMappers(name)
        self.setActiveWorkspace(workspace)
        notification_center.workspaceChanged(workspace)
        return workspace

    def closeWorkspace(self):
        # TODO: DELETE
        pass

    def removeWorkspace(self, name):
        if name in self.getWorkspacesNames():
            try:
                return delete_workspace(name)
            except Unauthorized:
                notification_center.showDialog("You are not authorized to "
                                               "delete this workspace. \n")

    def setActiveWorkspace(self, workspace):
        self.active_workspace = workspace

    def getActiveWorkspace(self):
        return self.active_workspace

    def workspaceExists(self, name):
        return name in self.getWorkspacesNames()

    def isActive(self, name):
        return self.active_workspace.getName() == name

    def isWorkspaceNameValid(self, ws_name):
        """Returns True if the ws_name is valid, else if it's not"""
        letters_or_numbers = r"^[a-z][a-z0-9\_\$()\+\-\/]*$"
        regex_name = re.match(letters_or_numbers, ws_name)
        if regex_name and regex_name.string not in CONST_BLACKDBS:
            return True
        else:
            return False
