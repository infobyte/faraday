'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from persistence.change import change_factory, CHANGETYPE
import model.guiapi


class ChangeController(object):
    def __init__(self, mapper_manager):
        self.mapper_manager = mapper_manager

    def notify(self, changes):
        for change in changes:
            model.guiapi.notification_center.changeFromInstance(change)

    def loadChange(self, objid, revision, deleted):
        obj = self.mapper_manager.find(objid)
        change = change_factory(obj, revision, deleted)
        if change.getChangeType() == CHANGETYPE.DELETE:
            self.mapper_manager.remove(objid)
        elif change.getChangeType() == CHANGETYPE.UPDATE:
            self.mapper_manager.reload(objid)
        model.guiapi.notification_center.changeFromInstance(change)
