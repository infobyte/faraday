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

    def isActive(self):
        return self.name == self._workspace_manager.getActiveWorkspace().name

    def getHosts(self):
        return self.hosts.values()

    def setHosts(self, hosts):
        self.hosts = hosts

