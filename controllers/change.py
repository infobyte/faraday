'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from persistence.change import change_factory, CHANGETYPE
import model.guiapi
import threading


class ChangeController(object):
    def __init__(self):
        self.mapper_manager = None
        self.changesWatcher = None

    def notify(self, changes):
        for change in changes:
            model.guiapi.notification_center.changeFromInstance(change)

    def loadChange(self, objid, revision, deleted):
        obj = self.mapper_manager.find(objid)
        change = change_factory.create(obj, revision, deleted)
        if change.getChangeType() == CHANGETYPE.DELETE:
            self.mapper_manager.remove(objid)
        elif change.getChangeType() == CHANGETYPE.UPDATE:
            self.mapper_manager.reload(objid)
        model.guiapi.notification_center.changeFromInstance(change)

    def watch(self, mapper, dbConnector):
        self.mapper_manager = mapper
        self.dbConnector = dbConnector
        self.changesWatcher = ChangeWatcher(dbConnector.waitForDBChange)
        dbConnector.setChangesCallback(self.loadChange) 
        self.changesWatcher.start()

    def unwatch(self):
        if self.changesWatcher:
            self.dbConnector.setChangesCallback(None)
            self.dbConnector.forceUpdate()
            self.changesWatcher.join()

    def stop(self):
        self.unwatch()

    def isAlive(self):
        return self.changesWatcher.isAlive()

class ChangeWatcher(threading.Thread):
    def __init__(self, watch_function):
        threading.Thread.__init__(self)

        self._function = watch_function
        self._watcher = threading.Thread(target=self._function)
        self._watcher.setDaemon(True)

    def run(self):
        self._watcher.start()

    def stop(self):
        self._stop_event.set()

