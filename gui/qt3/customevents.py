'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""
This module contains the definition of all the qt.QCustomEvent's used
in the application.
These events are needed to communicate secondary threads with the GUI.

"""
import qt
from gui.customevents import (LOGEVENT_ID, SHOWDIALOG_ID, SHOWPOPUP_ID,
                              EXCEPTION_ID, RENAMEHOSTSROOT_ID,
                              CLEARHOSTS_ID, DIFFHOSTS_ID, SYNCFAILED_ID,
                              CONFLICTS_ID, WORKSPACE_CHANGED, CONFLICT_UPDATE,
                              RESOLVECONFLICTS_ID, UPDATEMODEL_ID, ADDHOST,
                              EDITHOST, DELHOST, CHANGEFROMINSTANCE)


class LogCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.text = e.text


class ShowDialogCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.text = e.text


class ShowPopupCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.text = e.text
        self.level = e.level


class ShowExceptionCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.text = e.text
        self.exception_objects = e.exception_objects
        self.callback = e.callback


class RenameHostsRootCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.name = e.name


class WorkspaceChangedCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.workspace = e.workspace


class ConflictUpdatedCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.nconflicts = e.nconflicts


class DiffHostsCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.new_host = e.new_host
        self.old_host = e.old_host


class ResolveConflictsCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.conflicts = e.conflicts


class ClearHostsCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())


class ModelObjectUpdateEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.hosts = e.hosts


class AddHostCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.host = e.host


class EditHostCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.host = e.host


class DeleteHostCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.host_id = e.host_id


class ChangeFromInstanceCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type())
        self.change = e.change


class QtCustomEvent(qt.QCustomEvent):
    events = {
        LOGEVENT_ID: LogCustomEvent,
        SHOWDIALOG_ID: ShowDialogCustomEvent,
        SHOWPOPUP_ID: ShowPopupCustomEvent,
        EXCEPTION_ID: ShowExceptionCustomEvent,
        RENAMEHOSTSROOT_ID: RenameHostsRootCustomEvent,
        CLEARHOSTS_ID: ClearHostsCustomEvent,
        DIFFHOSTS_ID: DiffHostsCustomEvent,
        SYNCFAILED_ID: None,
        CONFLICTS_ID: None,
        WORKSPACE_CHANGED: WorkspaceChangedCustomEvent,
        CONFLICT_UPDATE: ConflictUpdatedCustomEvent,
        RESOLVECONFLICTS_ID: ResolveConflictsCustomEvent,
        UPDATEMODEL_ID: ModelObjectUpdateEvent,
        ADDHOST: AddHostCustomEvent,
        DELHOST: DeleteHostCustomEvent,
        EDITHOST: EditHostCustomEvent,
        CHANGEFROMINSTANCE: ChangeFromInstanceCustomEvent
    }

    @staticmethod
    def create(custom_event):
        return QtCustomEvent.events[custom_event.type()](custom_event)
