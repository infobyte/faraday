#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import model.api
import time
from model.guiapi import notification_center as notifier

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


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

