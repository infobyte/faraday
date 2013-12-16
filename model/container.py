#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

                                                         
from model.common import  ModelObjectDictAdapter
from model.hosts import Host
import model
from mockito import mock
import traceback

class ModelObjectContainer(dict):
                                   
    """Used to provide a consistent interface while adding model objects to the currently running environment"""
    def __init__(self, *args):
        self.container = {}

    def __setitem__(self, k, v):
                                       
        self.container.__setitem__(k, v) 

    def __getitem__(self, k):
        return self.container.get(k)

    def __getattr__( self, name):
        return getattr(self.container, name)

    def itervalues(self):
        return self.container.itervalues()

    def values(self):
        return self.container.values()

    def keys(self):
        return self.container.keys()

    def __str__(self):
        return str(self.container)

    def clear(self):
        self.container.clear()

    def __contains__(self, elem):
        return self.container.__contains__(elem)

    def containsByAttr(self, attrName, attrValue):
        for k, elem in self.container:
            if elem.__getattribute__(attrName) == attrValue:
                return True
        return False
        
    def __len__(self):
        return len(self.container)

    def __delitem__(self, k):
        self.container.__delitem__(k)


class CouchedModelObjectContainer(ModelObjectContainer):
    def __init__(self, workspaceName, couchManager):
        ModelObjectContainer.__init__(self)
        self.cdm = couchManager
        self.workspaceName = workspaceName

    def __setitem__(self, k, v):
        ModelObjectContainer.__setitem__(self, k, v)


