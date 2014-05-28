'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""
This module contains the definition of all the CustomEvent's used
in the application.
These events are needed to communicate secondary threads with the GUI.

"""

import time

LOGEVENT_ID = 3131
SHOWDIALOG_ID = 3132
SHOWPOPUP_ID = 3133
EXCEPTION_ID = 3134
RENAMEHOSTSROOT_ID = 3135
CLEARHOSTS_ID = 3136
DIFFHOSTS_ID = 3137
SYNCFAILED_ID = 3138
CONFLICTS_ID = 3139
WORKSPACE_CHANGED = 3140
CONFLICT_UPDATE = 3141
RESOLVECONFLICTS_ID = 3142
ADDHOST = 4100
DELHOST = 4101
EDITHOST = 4102
CHANGEFROMINSTANCE = 5100
UPDATEMODEL_ID = 54321


class CustomEvent(object):
    def __init__(self, type):
        self._type = type
        self._time = time.time()

    def type(self):
        return self._type

    def time(self):
        return self._time


class LogCustomEvent(CustomEvent):
    def __init__(self, text):
        CustomEvent.__init__(self, LOGEVENT_ID)
        self.text = text


class ShowDialogCustomEvent(CustomEvent):
    def __init__(self, text, type):
        CustomEvent.__init__(self, SHOWDIALOG_ID)
        self.text = text


class ShowPopupCustomEvent(CustomEvent):
    def __init__(self, text):
        CustomEvent.__init__(self, SHOWPOPUP_ID)
        self.text = text
        self.level = "INFORMATION"


class ShowExceptionCustomEvent(CustomEvent):
    def __init__(self, text, callback):
        CustomEvent.__init__(self, EXCEPTION_ID)
        self.text = text
        self.exception_objects = [None, text]
        self.callback = callback


class RenameHostsRootCustomEvent(CustomEvent):
    def __init__(self, name):
        CustomEvent.__init__(self, RENAMEHOSTSROOT_ID)
        self.name = name


class WorkspaceChangedCustomEvent(CustomEvent):
    def __init__(self, workspace):
        CustomEvent.__init__(self, WORKSPACE_CHANGED)
        self.workspace = workspace


class ConflictUpdatedCustomEvent(CustomEvent):
    def __init__(self, nconflicts):
        CustomEvent.__init__(self, CONFLICT_UPDATE)
        self.nconflicts = nconflicts


class DiffHostsCustomEvent(CustomEvent):
    def __init__(self, old_host, new_host):
        CustomEvent.__init__(self, DIFFHOSTS_ID)
        self.new_host = new_host
        self.old_host = old_host


class ResolveConflictsCustomEvent(CustomEvent):
    def __init__(self, conflicts):
        CustomEvent.__init__(self, RESOLVECONFLICTS_ID)
        self.conflicts = conflicts


class ClearHostsCustomEvent(CustomEvent):
    def __init__(self):
        CustomEvent.__init__(self, CLEARHOSTS_ID)


class ModelObjectUpdateEvent(CustomEvent):
    def __init__(self, hosts):
        CustomEvent.__init__(self, UPDATEMODEL_ID)
        self.hosts = hosts


class AddHostCustomEvent(CustomEvent):
    def __init__(self, host):
        CustomEvent.__init__(self, ADDHOST)
        self.host = host


class EditHostCustomEvent(CustomEvent):
    def __init__(self, host):
        CustomEvent.__init__(self, EDITHOST)
        self.host = host


class DeleteHostCustomEvent(CustomEvent):
    def __init__(self, host_id):
        CustomEvent.__init__(self, DELHOST)
        self.host_id = host_id


class ChangeFromInstanceCustomEvent(CustomEvent):
    def __init__(self, change):
        CustomEvent.__init__(self, CHANGEFROMINSTANCE)
        self.change = change
