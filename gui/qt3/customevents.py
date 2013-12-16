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

                                      
LOGEVENT_ID         = 3131
SHOWDIALOG_ID       = 3132
SHOWPOPUP_ID        = 3133
EXCEPTION_ID        = 3134
RENAMEHOSTSROOT_ID  = 3135
CLEARHOSTS_ID       = 3136
DIFFHOSTS_ID        = 3137
SYNCFAILED_ID       = 3138
CONFLICTS_ID        = 3139
WORKSPACE_CHANGED   = 3140
CONFLICT_UPDATE     = 3141
RESOLVECONFLICTS_ID = 3142

UPDATEMODEL_ID      = 54321

                                                                                
class LogCustomEvent(qt.QCustomEvent):
    def __init__(self, text):
        qt.QCustomEvent.__init__(self, LOGEVENT_ID)
        self.text = text

                                                                                

class ShowDialogCustomEvent(qt.QCustomEvent):
    def __init__(self, text, type):
        qt.QCustomEvent.__init__(self, SHOWDIALOG_ID)
        self.text = text

                                                                                

class ShowPopupCustomEvent(qt.QCustomEvent):
    def __init__(self, text):
        qt.QCustomEvent.__init__(self, SHOWPOPUP_ID)
        self.text = text
        self.level = "INFORMATION"
        
                                                                                

class ShowExceptionCustomEvent(qt.QCustomEvent):
    def __init__(self, text, callback):
        qt.QCustomEvent.__init__(self, EXCEPTION_ID)
        self.text = text        
        self.exception_objects = [None,text]
        self.callback = callback
        
                                                                                

class RenameHostsRootCustomEvent(qt.QCustomEvent):
    def __init__(self, name):
        qt.QCustomEvent.__init__(self, RENAMEHOSTSROOT_ID)
        self.name = name

class WorkspaceChangedCustomEvent(qt.QCustomEvent):
    def __init__(self, workspace):
        qt.QCustomEvent.__init__(self, WORKSPACE_CHANGED)
        self.workspace = workspace

class ConflictUpdatedCustomEvent(qt.QCustomEvent):
    def __init__(self, nconflicts):
        qt.QCustomEvent.__init__(self, CONFLICT_UPDATE)
        self.nconflicts = nconflicts
        
class DiffHostsCustomEvent(qt.QCustomEvent):
    def __init__(self, old_host, new_host):
        qt.QCustomEvent.__init__(self, DIFFHOSTS_ID)
        self.new_host = new_host
        self.old_host = old_host

class ResolveConflictsCustomEvent(qt.QCustomEvent):
    def __init__(self, conflicts):
        qt.QCustomEvent.__init__(self, RESOLVECONFLICTS_ID)
        self.conflicts = conflicts

                                                                                
class ClearHostsCustomEvent(qt.QCustomEvent):
    def __init__(self):
        qt.QCustomEvent.__init__(self, CLEARHOSTS_ID)
        
                                                                                

                                          
class ModelObjectUpdateEvent(qt.QCustomEvent):
    def __init__(self, hosts):
        qt.QCustomEvent.__init__(self, UPDATEMODEL_ID)
                         
                                 
                             
        self.hosts = hosts
