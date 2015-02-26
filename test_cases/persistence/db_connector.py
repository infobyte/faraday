#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import unittest
import sys
import os
import shutil
import json
sys.path.append(os.path.abspath(os.getcwd()))
from couchdbkit import Server, ResourceNotFound
import time

from persistence.persistence_managers import CouchDbConnector, FileSystemConnector
import random

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


def new_random_workspace_name():
    return ("aworkspace" + "".join(random.sample([chr(i) for i in range(65, 90)], 10))).lower()


class DbConnectorCouchTestSuite(unittest.TestCase):
    def setUp(self):
        self.couch_srv = Server(uri=CONF.getCouchURI())
        self.db_name = new_random_workspace_name()
        self.db = self.couch_srv.create_db(self.db_name)

    def tearDown(self):
        self.couch_srv.delete_db(self.db_name)
        time.sleep(3)

    def test_save_Document(self):
        couchConnector = CouchDbConnector(self.db)
        doc = {
            '_id': '123',
            'data': 'some data'
        }
        couchConnector.saveDocument(doc)

        doc_from_db = self.db.get('123')

        self.assertNotEquals(
            doc_from_db,
            None,
            "Document should be retrieved")

        self.assertEquals(
            doc_from_db.get('data'),
            'some data',
            "Data retrieved should be the same as data saved")

    def test_get_Document(self):
        couchConnector = CouchDbConnector(self.db)
        doc = {
            '_id': '123',
            'data': 'some data'
        }
        couchConnector.saveDocument(doc)

        doc_retrieved = couchConnector.getDocument('123')

        self.assertNotEquals(
            doc_retrieved,
            None,
            "Document should be retrieved")

        self.assertEquals(
            doc_retrieved.get('data'),
            'some data',
            "Data retrieved should be the same as data saved")

    def test_remove_Document(self):
        couchConnector = CouchDbConnector(self.db)
        doc = {
            '_id': '123',
            'data': 'some data'
        }
        couchConnector.saveDocument(doc)

        couchConnector.remove('123')

        try:
            doc_from_db = self.db.get('123')
        except ResourceNotFound:
            doc_from_db = None

        self.assertEquals(
            doc_from_db,
            None,
            "Document should be None")

    def test_get_by_parent_and_type(self):
        couchConnector = CouchDbConnector(self.db)
        doc = {
            '_id': '123',
            'type': 'father',
            'parent': None,
        }
        couchConnector.saveDocument(doc)

        doc = {
            '_id': '456',
            'type': 'child',
            'parent': '123',
        }
        couchConnector.saveDocument(doc)

        doc = {
            '_id': '789',
            'type': 'child',
            'parent': '123',
        }
        couchConnector.saveDocument(doc)

        ids = couchConnector.getDocsByFilter(parentId='123', type='child')

        self.assertEquals(
            len(ids),
            2,
            "There should be two 'childs' with parent '123'")

        self.assertIn(
            '456',
            ids,
            "Child '456' should be in the list of childs")

        self.assertIn(
            '789',
            ids,
            "Child '789' should be in the list of childs")

        ids = couchConnector.getDocsByFilter(parentId='123', type='son')

        self.assertEquals(
            len(ids),
            0,
            "There shouldn't be any 'son' with parent '123'")

        ids = couchConnector.getDocsByFilter(parentId='456', type='child')

        self.assertEquals(
            len(ids),
            0,
            "There shouldn't be any 'child' with parent '456'")


class DbConnectorFileSystemTestSuite(unittest.TestCase):
    def setUp(self):
        self.path = CONF.getPersistencePath()
        self.db_path = os.path.join(self.path, new_random_workspace_name())
        os.mkdir(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.db_path)

    def test_save_Document(self):
        fsConnector = FileSystemConnector(self.db_path)
        doc = {
            '_id': '123',
            'data': 'some data'
        }
        fsConnector.saveDocument(doc)

        doc_from_db = open(os.path.join(self.db_path, '%s.json' % '123'), 'r')
        doc_from_db = json.loads(doc_from_db.read())

        self.assertNotEquals(
            doc_from_db,
            None,
            "Document should be retrieved")

        self.assertEquals(
            doc_from_db.get('data'),
            'some data',
            "Data retrieved should be the same as data saved")

    def test_get_Document(self):
        fsConnector = FileSystemConnector(self.db_path)
        doc = {
            '_id': '123',
            'data': 'some data'
        }
        fsConnector.saveDocument(doc)

        doc_retrieved = fsConnector.getDocument('123')

        self.assertNotEquals(
            doc_retrieved,
            None,
            "Document should be retrieved")

        self.assertEquals(
            doc_retrieved.get('data'),
            'some data',
            "Data retrieved should be the same as data saved")

    def test_remove_Document(self):
        fsConnector = FileSystemConnector(self.db_path)
        doc = {
            '_id': '123',
            'data': 'some data'
        }
        fsConnector.saveDocument(doc)

        fsConnector.remove('123')

        try:
            doc_from_db = open(os.path.join(self.db_path, '%s.json' % '123'), 'r')
            doc_from_db = json.loads(doc_from_db.read())
        except IOError:
            doc_from_db = None

        self.assertEquals(
            doc_from_db,
            None,
            "Document should be None")

    def test_get_by_parent_and_type(self):
        fsConnector = FileSystemConnector(self.db_path)
        doc = {
            '_id': '123',
            'type': 'father',
            'parent': None,
        }
        fsConnector.saveDocument(doc)

        doc = {
            '_id': '456',
            'type': 'child',
            'parent': '123',
        }
        fsConnector.saveDocument(doc)

        doc = {
            '_id': '789',
            'type': 'child',
            'parent': '123',
        }
        fsConnector.saveDocument(doc)

        ids = fsConnector.getDocsByFilter(parentId='123', type='child')

        self.assertEquals(
            len(ids),
            2,
            "There should be two 'childs' with parent '123'")

        self.assertIn(
            '456',
            ids,
            "Child '456' should be in the list of childs")

        self.assertIn(
            '789',
            ids,
            "Child '789' should be in the list of childs")

        ids = fsConnector.getDocsByFilter(parentId='123', type='son')

        self.assertEquals(
            len(ids),
            0,
            "There shouldn't be any 'son' with parent '123'")

        ids = fsConnector.getDocsByFilter(parentId='456', type='child')

        self.assertEquals(
            len(ids),
            0,
            "There shouldn't be any 'child' with parent '456'")

if __name__ == '__main__':
    unittest.main()
