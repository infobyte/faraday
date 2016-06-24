'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from persistence.change import change_factory, CHANGETYPE, ChangeModelObject
import model
import model.guiapi
import threading
from utils.logs import getLogger


class ChangeController(object):
    def __init__(self):
        self.mapper_manager = None
        self.changesWatcher = None

    def notify(self, changes):
        for change in changes:
            model.guiapi.notification_center.changeFromInstance(change)

    def loadChange(self, objid, revision, deleted):
        try:
            obj = self.mapper_manager.find(objid)
            change = change_factory.create(obj, revision, deleted)

            if change.getChangeType() == CHANGETYPE.DELETE:
                # object deleted
                if isinstance(change, ChangeModelObject):
                    obj_parent = obj.getParent()
                    if obj_parent:
                        obj_parent.deleteChild(obj.getID())
                self.mapper_manager.remove(objid)
            elif change.getChangeType() == CHANGETYPE.UPDATE:
                # object edited
                self.mapper_manager.reload(objid)
            elif change.getChangeType() == CHANGETYPE.ADD:
                if isinstance(change, ChangeModelObject):
                    # The child has a parent, but the parent doesn't
                    # have the child yet...
                    if obj.getParent():
                        obj.getParent().addChild(obj)

            if isinstance(change, ChangeModelObject):
                self._notify_model_object_change(change, obj)
            model.guiapi.notification_center.changeFromInstance(change)
        except:
            getLogger(self).debug(
                "Change couldn't be processed")

    def _notify_model_object_change(self, change, obj):
        host = obj.getHost()
        if (change.getChangeType() == CHANGETYPE.ADD and
           obj.class_signature == model.hosts.Host.class_signature):
            model.guiapi.notification_center.addHost(host)
        elif (change.getChangeType() == CHANGETYPE.DELETE and
              obj.class_signature == model.hosts.Host.class_signature):
            model.guiapi.notification_center.delHost(host.getID())
        elif (change.getChangeType() != CHANGETYPE.UNKNOWN):
            model.guiapi.notification_center.editHost(host)

    def manageConnectionLost(self):
        """All it does is send a notification to the notification center"""
        model.guiapi.notification_center.CouchDBConnectionProblem()

    def watch(self, mapper, dbConnector):
        self.mapper_manager = mapper
        self.dbConnector = dbConnector
        self.changesWatcher = ChangeWatcher(dbConnector.waitForDBChange)
        dbConnector.setChangesCallback(self.loadChange)
        dbConnector.setCouchExceptionCallback(self.manageConnectionLost)
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

