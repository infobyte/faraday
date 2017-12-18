'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''
import logging

from persistence.server.models import create_object, get_object, update_object, delete_object

# NOTE: This class is intended to be instantiated by the
# service or controller that needs it.
# IMPORTANT: There should be only one instance of this
# class, since it creates the datamappers and those should
# be unique too (they have identity maps for every model object)
logger = logging.getLogger(__name__)


class MapperManager(object):
    def __init__(self):
        # create and store the datamappers
        self.workspace_name = None
        self.session = None

    def createMappers(self, workpace_name):
        self.workspace_name = workpace_name

    def save(self, obj, command_id=None):
        saved_raw_obj = create_object(self.workspace_name, obj.class_signature, obj, command_id)
        if '_id' in saved_raw_obj:
            return saved_raw_obj['_id']
        return False
    
    def update(self, obj, command_id=None):
        if update_object(self.workspace_name, obj.class_signature, obj, command_id):
            return True
        return False

    def find(self, class_signature, obj_id):
        if self.workspace_name is None:
            logger.warn('No workspace detected. please call createMappers first.')
        return get_object(self.workspace_name, class_signature, obj_id)

    def remove(self, obj_id, class_signature):
        return delete_object(self.workspace_name, class_signature, obj_id)