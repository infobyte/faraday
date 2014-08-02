'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from persistence.persistence_managers import DbConnector


class NullPersistenceManager(DbConnector):
    def __init__(self):
        super(NullPersistenceManager, self).__init__()

    def saveDocument(self, document):
        pass

    def getDocument(self, documentId):
        return None

    def remove(self, documentId):
        return True

    def getDocsByFilter(self, parentId, type):
        return []


class AbstractMapper(object):
    mapped_class = None
    dummy_args = []
    dummy_kwargs = {}

    def __init__(self, mmanager, pmanager=None):
        self.mapper_manager = mmanager
        self.pmanager = pmanager if pmanager else NullPersistenceManager()
        self.object_map = {}

    def setPersistenceManager(self, pmanager):
        self.pmanager = pmanager

    def save(self, obj):
        #save the object first
        doc = self.serialize(obj)
        self.pmanager.saveDocument(doc)

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
        doc = self.pmanager.getDocument(id)
        if not doc or not doc.get("type") == self.mapped_class.__name__:
            return None
        obj = self.mapped_class(*self.dummy_args, **self.dummy_kwargs)
        obj.setID(doc.get("_id"))
        self.object_map[obj.getID()] = obj
        self.unserialize(obj, doc)
        return obj

    def reload(self, obj):
        doc = self.pmanager.getDocument(obj.getID())
        self.unserialize(obj, doc)

    def update(self, obj):
        self.serialize(obj)
        self.pmanager.saveDocument(obj)

    def delete(self, id):
        obj = None
        self.pmanager.remove(id)
        if id in self.object_map.keys():
            obj = self.object_map.get(id)
            del self.object_map[id]
        return obj

    def find(self, id, with_load=True):
        if not id:
            return None
        if self.object_map.get(id):
            return self.object_map.get(id)
        return self.load(id)


    def findByFilter(self, parent, type):
        result = []
        ids = self.pmanager.getDocsByFilter(parent, type)
        for id in ids:
            obj = self.load(id)
            result.append(obj)
        return result
