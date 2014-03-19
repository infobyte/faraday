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
import gui.customevents


class LogCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.text = e.text


class ShowDialogCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.text = e.text


class ShowPopupCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.text = e.text
        self.level = e.level


class ShowExceptionCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.text = e.text
        self.exception_objects = e.exception_objects
        self.callback = e.callback


class RenameHostsRootCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.name = e.name


class WorkspaceChangedCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.workspace = e.workspace


class ConflictUpdatedCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.nconflicts = e.nconflicts


class DiffHostsCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.new_host = e.new_host
        self.old_host = e.old_host


class ResolveConflictsCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.conflicts = e.conflicts


class ClearHostsCustomEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)


class ModelObjectUpdateEvent(qt.QCustomEvent):
    def __init__(self, e):
        qt.QCustomEvent.__init__(self, e.type)
        self.hosts = e.hosts


class QtCustomEvent(qt.QCustomEvent):
    events = {
        gui.customevents.LOGEVENT_ID: LogCustomEvent,
        gui.customevents.SHOWDIALOG_ID: ShowDialogCustomEvent,
        gui.customevents.SHOWPOPUP_ID: ShowPopupCustomEvent,
        gui.customevents.EXCEPTION_ID: ShowExceptionCustomEvent,
        gui.customevents.RENAMEHOSTSROOT_ID: RenameHostsRootCustomEvent,
        gui.customevents.CLEARHOSTS_ID: ClearHostsCustomEvent,
        gui.customevents.DIFFHOSTS_ID: DiffHostsCustomEvent,
        gui.customevents.SYNCFAILED_ID: None,
        gui.customevents.CONFLICTS_ID: None,
        gui.customevents.WORKSPACE_CHANGED: WorkspaceChangedCustomEvent,
        gui.customevents.CONFLICT_UPDATE: ConflictUpdatedCustomEvent,
        gui.customevents.RESOLVECONFLICTS_ID: ResolveConflictsCustomEvent,
        gui.customevents.UPDATEMODEL_ID: ModelObjectUpdateEvent
    }

    @staticmethod
    def create(custom_event):
        return QtCustomEvent.events[custom_event.type](custom_event)


    # def create(custom_event):
    #     pass
