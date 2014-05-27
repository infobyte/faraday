'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import model
import threading
import traceback
from controller.change import ChangeController


class WorkspacePersister(object):
    _instance = None
    _persister = None
    _workspace = None
    _workspace_autoloader = None
    _pending_actions = None
    _change_controller = ChangeController()

    def __new__(cls, *args, **kargs):
        if cls._instance is None:
            cls._instance = object.__new__(cls, *args, **kargs)
        return cls._instance

    def setPersister(self, workspace, persister):
        WorkspacePersister._persister = persister
        WorkspacePersister._workspace = workspace
        WorkspacePersister._change_controller.setWorkspace(workspace)
        WorkspacePersister._workspace_autoloader = WorkspaceAutoSync(self.loadChanges, self.backendChangeListener)
        WorkspacePersister._workspace_autoloader.start()
        WorkspacePersister._pending_actions = PendingTransactionsQueue()

    @staticmethod
    def stopThreads():
        WorkspacePersister._workspace_autoloader.stop()

    def loadChanges(self, changes):
        self._change_controller.loadChanges(changes)

    def reloadWorkspace(self):
        WorkspacePersister._workspace.load()

    @staticmethod
    def addPendingAction(obj, func, args, kwargs):
        if "wait" not in func.__name__:
            WorkspacePersister._pending_actions.pushPendingTransaction(obj, func, args, kwargs)

    @staticmethod
    def reExecutePendingActions():
        for (obj, func, args, kwargs) in WorkspacePersister._pending_actions:
            func(obj, *args, **kwargs)
            
        model.api.devlog("Re executing")

    @staticmethod
    def notifyPersisterConnectionLost():
        WorkspacePersister._workspace.notifyWorkspaceNoConnection()

    def backendChangeListener(self): 
        changes = WorkspacePersister._persister.waitForDBChange(WorkspacePersister._workspace.name)
        return changes

    @staticmethod
    def save(obj):
        if WorkspacePersister._workspace is not None:
            WorkspacePersister._workspace.saveObj(obj)

    @staticmethod
    def delete(obj):
        if WorkspacePersister._workspace:
            WorkspacePersister._workspace.delObj(obj)

class WorkspaceAutoSync(threading.Thread):
    def __init__(self, action_callback, listener):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self._stop = False
        self._listener = listener
        self._action = action_callback

    def run(self):
        while not self._stop:
            try:
                result = self._listener()
                if result:
                    model.api.devlog("Changes found: %s" % result)
                    self._action(result)
            except Exception, e:
                model.api.devlog("An exception was captured while saving workspaces\n%s" % traceback.format_exc())

    def stop(self):
        self._stop = True

    def start(self):
        self._stop = False
        threading.Thread.start(self)


class PendingTransactionsQueue(object):
    def __init__(self):
        self.pending = []

    def pushPendingTransaction(self, obj, func, args, kwargs):
        self.pending.insert(0, (obj, func, args, kwargs))

    def __iter__(self):
        return self

    def next(self):
        try:
            return self.pending.pop()
        except IndexError:
            raise StopIteration 

