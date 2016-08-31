#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import threading
from gui.gui_app import FaradayUi
import gui.customevents as events


class NotificationCenter():
    def __init__(self, uiapp=FaradayUi(None, None, None, None, None)):
        self.uiapp = uiapp
        self._consumers = []
        self._consumers_lock = threading.RLock()
        self.last_events = {}

    def setUiApp(self, uiapp):
        self.uiapp = uiapp

    def registerWidget(self, consumer):
        self._consumers_lock.acquire()
        if consumer not in self._consumers:
            self._consumers.append(consumer)
        self._consumers_lock.release()

    def deregisterWidget(self, consumer):
        self._consumers_lock.acquire()
        if consumer in self._consumers:
            self._consumers.remove(consumer)
        self._consumers_lock.release()

    def postCustomEvent(self, event, receiver=None):
        if self.last_events.get(event.type(), None):
            if self.last_events[event.type()] > event.time():
                return
        self.last_events[event.type()] = event.time()
        self.uiapp.postEvent(receiver, event)

    def _notifyWidgets(self, event):
        self._consumers_lock.acquire()
        for w in self._consumers:
            self.postCustomEvent(event, w)
        self._consumers_lock.release()

    def showPopup(self, msg):
        self._notifyWidgets(events.ShowPopupCustomEvent(msg))

    def showDialog(self, msg, level="INFORMATION"):
        self._notifyWidgets(events.ShowDialogCustomEvent(msg, level))

    def workspaceChanged(self, workspace):
        self._notifyWidgets(events.WorkspaceChangedCustomEvent(workspace))

    def CouchDBConnectionProblem(self, problem=None):
        self._notifyWidgets(events.ShowExceptionConnectionRefusedCustomEvent(problem))

    def WorkspaceProblem(self, problem=None):
        self._notifyWidgets(events.WorkspaceProblemCustomEvent(problem))

    def addHost(self, host):
        self._notifyWidgets(events.AddHostCustomEvent(host))

    def delHost(self, host_id):
        self._notifyWidgets(events.DeleteHostCustomEvent(host_id))

    def editHost(self, host):
        self._notifyWidgets(events.EditHostCustomEvent(host))

    def conflictUpdate(self, vulns_changed):
        self._notifyWidgets(events.ConflictUpdatedCustomEvent(vulns_changed))

    def conflictResolution(self, conflicts):
        self._notifyWidgets(events.ResolveConflictsCustomEvent(conflicts))

    def changeFromInstance(self, obj_type, obj_name, deleted):
        self._notifyWidgets(events.ChangeFromInstanceCustomEvent(obj_type, obj_name, deleted))

    def addHostFromChanges(self, obj):
        self._notifyWidgets(events.AddHostChangesEvent(obj))

    def editObject(self, obj):
        self._notifyWidgets(events.UpdateObjectCustomEvent(obj))

    def deleteObject(self, obj):
        self._notifyWidgets(events.DeleteObjectCustomEvent(obj))

    def addObject(self, new_object):
        self._notifyWidgets(events.AddObjectCustomEvent(new_object))
