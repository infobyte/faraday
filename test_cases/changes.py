#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import unittest
import sys
sys.path.append('.')
import model.controller as controller
from mockito import mock, verify, when, any
from model.hosts import Host, Interface, Service
from model.common import ModelObjectVuln, ModelObjectVulnWeb, ModelObjectNote, ModelObjectCred
from urlparse import urlparse
from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()
from utils.logs import getLogger
from couchdbkit import Server, ChangesStream, Database
from controllers.change import ChangeController
from persistence.persistence_managers import CouchDbConnector, CouchDbManager


class ModelChanges(unittest.TestCase):
    def testThreadStops(self):
        changes_controller = ChangeController()
        mapper = mock()
        uri = CONF.getCouchURI()
        url = urlparse(uri)
        getLogger(self).debug(
            "Setting user,pass %s %s" % (url.username, url.password))
        self.cdbManager = CouchDbManager(uri=uri)
        
        dbCouchController = self.cdbManager.createDb('testWkspc')
        dbCouchController.saveDocument({'_id':'testwkspc',
                                    'type':'workspace' })

        changes_controller.watch(mapper, dbCouchController)
        self.assertTrue(changes_controller.isAlive())

        changes_controller.unwatch()
        self.assertFalse(changes_controller.isAlive())
        

if __name__ == '__main__':
    unittest.main() 

