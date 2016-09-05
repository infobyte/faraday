'''
Faraday Penetration Test IDE
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
CONNECTION_REFUSED = 42424
WORKSPACE_PROBLEM = 24242
ADDOBJECT = 7777
DELETEOBJECT = 8888
UPDATEOBJECT = 9999

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
    def __init__(self, text, level):
        CustomEvent.__init__(self, SHOWDIALOG_ID)
        self.text = text
        self.level = level


class ShowPopupCustomEvent(CustomEvent):
    def __init__(self, text):
        CustomEvent.__init__(self, SHOWPOPUP_ID)
        self.text = text
        self.level = "INFORMATION"


class ShowExceptionCustomEvent(CustomEvent):
    def __init__(self, text, callback, error_name=None):
        CustomEvent.__init__(self, EXCEPTION_ID)
        self.text = text
        self.exception_objects = [None, text]
        self.callback = callback
        if error_name is not None:
            self.error_name = error_name

# this is probably a bad name for the class
# maybe ConnectionRefusedCustomEven would've been better
class ShowExceptionConnectionRefusedCustomEvent(CustomEvent):
    def __init__(self, problem=None):
        CustomEvent.__init__(self, CONNECTION_REFUSED)
        self.problem = problem

class WorkspaceProblemCustomEvent(CustomEvent):
    def __init__(self, problem=None):
        CustomEvent.__init__(self, WORKSPACE_PROBLEM)
        self.problem = problem


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
    def __init__(self, object_id, object_type, object_name,
                 deleted=False, updated=False):
        CustomEvent.__init__(self, CHANGEFROMINSTANCE)
        self.object_id = object_id
        self.object_type = object_type
        self.object_name = object_name
        self.deleted = deleted
        self.updated_or_created = "updated" if updated else "created"

    def __str__(self):
        if self.deleted:
            return "The object of ID {0} was deleted".format(self.object_id)
        return "The {0} {1} was {2}".format(self.object_type,
                                            self.object_name,
                                            self.updated_or_created)

class AddObjectCustomEvent(CustomEvent):
    def __init__(self, new_obj):
        CustomEvent.__init__(self, ADDOBJECT)
        self.new_obj = new_obj

class DeleteObjectCustomEvent(CustomEvent):
    def __init__(self, obj_id):
        CustomEvent.__init__(self, DELETEOBJECT)
        self.obj_id = obj_id

class UpdateObjectCustomEvent(CustomEvent):
    def __init__(self, obj):
        CustomEvent.__init__(self, UPDATEOBJECT)
        self.obj = obj
