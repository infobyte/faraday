#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import unittest
import sys
import os
sys.path.append(os.path.abspath(os.getcwd()))
import random
from couchdbkit import Server

from persistence.persistence_managers import CouchDbManager, FileSystemManager

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


def new_random_workspace_name():
    return ("aworkspace" + "".join(random.sample([chr(i) for i in range(65, 90)], 10))).lower()


class CouchDbManagerTestSuite(unittest.TestCase):
    def setUp(self):
        self.dbname = new_random_workspace_name()

    def tearDown(self):
        server = Server(uri=CONF.getCouchURI())
        if self.dbname in server.all_dbs():
            server.delete_db(self.dbname)

    def test_create_and_get_db(self):
        couch_manager = CouchDbManager(uri=CONF.getCouchURI())
        couch_manager.createDb(self.dbname)

        self.assertNotEquals(
            couch_manager.getDb(self.dbname),
            None,
            "Db %s shouldn't be None" % self.dbname)

        server = Server(uri=CONF.getCouchURI())
        self.assertIn(
            self.dbname,
            server.all_dbs(),
            "Db %s should be in the db list" % self.dbname)

    def test_delete_db(self):
        couch_manager = CouchDbManager(uri=CONF.getCouchURI())
        couch_manager.createDb(self.dbname)

        self.assertNotEquals(
            couch_manager.getDb(self.dbname),
            None,
            "Db %s shouldn't be None" % self.dbname)

        couch_manager.deleteDb(self.dbname)
        self.assertEquals(
            couch_manager.getDb(self.dbname),
            None,
            "Db %s should be None" % self.dbname)

        server = Server(uri=CONF.getCouchURI())
        self.assertNotIn(
            self.dbname,
            server.all_dbs(),
            "Db %s shouldn't be in the db list" % self.dbname)


if __name__ == '__main__':
    unittest.main()
