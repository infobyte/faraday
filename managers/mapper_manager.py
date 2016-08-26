'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from persistence.models import create_object, get_object, update_object, delete_object

# NOTE: This class is intended to be instantiated by the
# service or controller that needs it.
# IMPORTANT: There should be only one instance of this
# class, since it creates the datamappers and those should
# be unique too (they have identity maps for every model object)


class MapperManager(object):
    def __init__(self):
        # create and store the datamappers
        self.mappers = {}
        self.workspace_name = None

    def createMappers(self, workpace_name):
        self.workspace_name = workpace_name

    def save(self, obj):
        if create_object(self.workspace_name, obj.class_signature, obj):
            return True
        return False
    
    def update(self, obj):
        if update_object(self.workspace_name, obj.class_signature, obj):
            return True
        return False

    def find(self, class_signature, obj_id):
        return get_object(self.workspace_name, class_signature, obj_id)

    def remove(self, obj_id):
        return delete_object(self.workspace_name, class_signature, obj)