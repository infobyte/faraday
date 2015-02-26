'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''


from persistence.mappers.data_mappers import Mappers

# NOTE: This class is intended to be instantiated by the
# service or controller that needs it.
# IMPORTANT: There should be only one instance of this
# class, since it creates the datamappers and those should
# be unique too (they have identity maps for every model object)


class MapperManager(object):
    def __init__(self):
        # create and store the datamappers
        self.mappers = {}

    def createMappers(self, dbconnector):
        self.mappers.clear()
        for tmapper, mapper in Mappers.items():
            self.mappers[tmapper] = mapper(self, dbconnector)

    def save(self, obj):
        if self.mappers.get(obj.class_signature, None):
            self.mappers.get(obj.class_signature).save(obj)
            return True
        return False

    def find(self, obj_id):
        obj = self._find(obj_id, with_load=False)
        if not obj:
            obj = self._find(obj_id, with_load=True)
        return obj

    def _find(self, obj_id, with_load=True):
        for mapper in self.mappers.values():
            obj = mapper.find(obj_id, with_load=with_load)
            if obj:
                return obj
        return None

    def remove(self, obj_id):
        obj = self.find(obj_id)
        if obj:
            self.mappers.get(obj.class_signature).delete(obj_id)
            return True
        return False

    def reload(self, obj_id):
        obj = self.find(obj_id)
        if obj:
            self.mappers.get(obj.class_signature).reload(obj)

    def getMapper(self, type):
        return self.mappers.get(type, None)
