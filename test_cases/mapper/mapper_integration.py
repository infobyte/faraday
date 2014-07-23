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
import random
sys.path.append(os.path.abspath(os.getcwd()))

from mockito import mock, when, any

from model.hosts import Host, Interface, Service
from persistence.mappers.data_mappers import HostMapper, InterfaceMapper, ServiceMapper
from persistence.mappers.abstract_mapper import NullPersistenceManager
from managers.all import CouchdbManager

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

class MapperWithCouchPersistenceManagerInegrationTest(unittest.TestCase):
    def setUp(self):
        self.db_name = self.new_random_workspace_name()
        self.couchdbmanager = CouchdbManager(CONF.getCouchURI(),
                                             self.db_name)
        if not self.couchdbmanager.workspaceExists(self.db_name):
            self.couchdbmanager.addWorkspace(self.db_name)
        self.hmapper = HostMapper(self.couchdbmanager)

    def new_random_workspace_name(self):
        return ("aworkspace" + "".join(random.sample(
            [chr(i) for i in range(65, 90)], 10))).lower()

    def tearDown(self):
        self.couchdbmanager.removeWorkspace(self.db_name)

    def test_host_saving(self):
        self.assertTrue(self.couchdbmanager.isAvailable(),
                        "Couchdb should be available")

        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.hmapper.save(host)

        self.assertNotEquals(
            self.couchdbmanager.getDocument(host.getID()),
            None,
            "Document shouldn't be None")

        self.assertEquals(
            self.couchdbmanager.getDocument(host.getID()).get("name"),
            host.getName(),
            "Document should have the same host name")

    def test_load_nonexistent_host(self):
        self.assertEquals(
            self.couchdbmanager.getDocument("1234"),
            None,
            "Nonexistent host should return None document")

        self.assertEquals(
            self.hmapper.load("1234"),
            None,
            "Nonexistent host should return None object")

    def test_find_not_loaded_host(self):
        self.assertTrue(self.couchdbmanager.isAvailable(),
                        "Couchdb should be available")

        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.hmapper.save(host)

        #create a new host mapper, so we have a clean map
        self.hmapper = HostMapper(self.couchdbmanager)

        h = self.hmapper.find(host.getID())
        self.assertNotEquals(
            h,
            None,
            "Existent host shouldn't return None")

        self.assertEquals(
            h.getName(),
            "pepito",
            "Host name should be pepito")

        self.assertEquals(
            h.getOS(),
            "linux",
            "Host os should be linux")

    def test_host_create_and_delete(self):
        host = Host(name="http")
        self.hmapper.save(host)
        h_id = host.getID()

        self.assertNotEquals(
            self.hmapper.load(h_id),
            None,
            "Host should be saved")

        self.hmapper.delete(h_id)

        self.assertEquals(
            self.hmapper.load(h_id),
            None,
            "Host shouldn't exist anymore")
