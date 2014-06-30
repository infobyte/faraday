'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from managers.all import PersistenceManager


class NullPersistenceManager(PersistenceManager):
    def saveDocument(self, db, document):
        pass

    def get(self, db, documentId):
        return None

    def delete(self, db, documentId):
        return True


class AbstractMapper(object):

    def __init__(self, pmanager=None):
        self.pmanager = pmanager if pmanager else NullPersistenceManager()
        self.object_map = {}

    def setPersistenceManager(self, pmanager):
        self.pmanager = pmanager

    def save(self, obj):
        #save the object first
        obj = self.serialize(obj)
        self.pmanager.saveDocument(obj)

        #then add it to the IdentityMap
        self.object_map[obj.getID()] = obj
        return obj.getID()

    def serialize(self, obj):
        raise NotImplementedError("AbstractMapper should not be used directly")

    def unserialize(self, doc):
        raise NotImplementedError("AbstractMapper should not be used directly")

    def load(self, id):
        if id in self.object_map.keys():
            return self.object_map.get(id)
        doc = self.pmanager.get(id)
        obj = self.unserialize(doc)
        if obj:
            self.object_map[obj.getID()] = obj
        return obj

    def update(self, obj):
        self.serialize(obj)
        self.pmanager.saveDocument(obj)

    def delete(self, id):
        obj = None
        self.pmanager.delete(id)
        if id in self.object_map.keys():
            obj = self.object_map.get(id)
            del self.object_map[id]
        return obj

    def find(self, id):
        if self.object_map.get(id):
            return self.object_map.get(id)
        return self.load(id)
