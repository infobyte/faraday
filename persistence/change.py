'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from model.common import (ModelObjectNote, ModelObjectCred, ModelObjectVuln,
                          ModelObjectVulnWeb)
from model.hosts import Host, Interface, Service


class CHANGETYPE(object):
    ADD = 1,
    UPDATE = 2
    DELETE = 3
    UNKNOWN = 999


class ChangeFactory(object):
    def __init__(self):
        pass

    def create(self, obj, revision, deleted):
        change_type = CHANGETYPE.UNKNOWN
        if deleted:
            change_type = CHANGETYPE.DELETE
        elif int(revision[0]) > 1:
            change_type = CHANGETYPE.UPDATE
        else:
            change_type = CHANGETYPE.ADD

        obj_type = obj.class_signature
        if obj_type in [Host.class_signature,
                        Interface.class_signature,
                        Service.class_signature,
                        ModelObjectNote.class_signature,
                        ModelObjectVuln.class_signature,
                        ModelObjectVulnWeb.class_signature,
                        ModelObjectCred.class_signature,
                        'unknown']:
            return ChangeModelObject(obj, change_type)
        else:
            return ChangeCmd(obj, change_type)


class Change(object):
    def __init__(self, obj, change_type):
        self.change_type = change_type
        self.object = obj
        self.msg = "Change: Action: %s - Type: %s" % (
            self.change_type, self.obj.class_signature)

    def getObject(self):
        return self.object

    def getChangeType(self):
        return self.change_type

    def getMessage(self):
        return self.msg


class ChangeModelObject(Change):
    def __init__(self, obj, change_type):
        Change.__init__(self, obj, change_type)
        if self.change_type == CHANGETYPE.DELETE:
            self.msg = "%s %s deleted" % (
                self.object.class_signature, self.object.getName())
        elif self.change_type == CHANGETYPE.UPDATE:
            self.msg = "%s %s updated" % (
                self.object.class_signature, self.object.getName())
        elif self.change_type == CHANGETYPE.ADD:
            self.msg = "%s %s added" % (
                self.object.class_signature, self.object.getName())


class ChangeCmd(Change):
    def __init__(self, obj, change_type):
        Change.__init__(self, obj, change_type)
        if self.change_type == CHANGETYPE.UPDATE:
            self.msg = "Command finished: %s %s" % (
                self.object.get("command"), self.object.get("params"))
        elif self.change_type == CHANGETYPE.ADD:
            self.msg = "Command finished: %s %s" % (
                self.object.get("command"), self.object.get("params"))


change_factory = ChangeFactory()
