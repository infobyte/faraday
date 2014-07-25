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

from persistence.persistence_managers import CouchDbManager, FileSystemManager
from persistence.mappers.mapper_manager import MapperManager

from model.hosts import Host, Interface

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class MapperWithCouchDbManagerInegrationTest(unittest.TestCase):
    def setUp(self):
        self.db_name = self.new_random_workspace_name()

        self.couchdbmanager = CouchDbManager(CONF.getCouchURI())

        self.connector = self.couchdbmanager.createDb(self.db_name)
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(self.connector)

    def new_random_workspace_name(self):
        return ("aworkspace" + "".join(random.sample(
            [chr(i) for i in range(65, 90)], 10))).lower()

    def tearDown(self):
        self.couchdbmanager.deleteDb(self.db_name)

    def test_host_saving(self):
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)

        self.assertNotEquals(
            self.connector.getDocument(host.getID()),
            None,
            "Document shouldn't be None")

        self.assertEquals(
            self.connector.getDocument(host.getID()).get("name"),
            host.getName(),
            "Document should have the same host name")

    def test_load_nonexistent_host_using_manager_find(self):
        self.assertEquals(
            self.connector.getDocument("1234"),
            None,
            "Nonexistent host should return None document")

        self.assertEquals(
            self.mapper_manager.find("1234"),
            None,
            "Nonexistent host should return None object")

    def test_load_nonexistent_host_using_mapper_find(self):
        self.assertEquals(
            self.connector.getDocument("1234"),
            None,
            "Nonexistent host should return None document")

        self.assertEquals(
            self.mapper_manager.getMapper(Host.__name__).find("1234"),
            None,
            "Nonexistent host should return None object")

    def test_find_not_loaded_host(self):
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)

        #create a set of mappers, so we have a clean map
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(self.connector)

        h = self.mapper_manager.find(host.getID())
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
        host = Host(name="coquito")
        self.mapper_manager.save(host)
        h_id = host.getID()

        self.assertNotEquals(
            self.mapper_manager.find(h_id),
            None,
            "Host should be in the mapper")

        self.assertNotEquals(
            self.connector.getDocument(h_id),
            None,
            "Host should be in the db")

        self.mapper_manager.remove(h_id)

        self.assertEquals(
            self.mapper_manager.find(h_id),
            None,
            "Host shouldn't exist anymore in the mapper")

        self.assertEquals(
            self.connector.getDocument(h_id),
            None,
            "Host shouldn't exist anymore in the db")

    def test_composite_host(self):
        # add host
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)
        # add inteface
        iface = Interface(name="192.168.10.168", mac="01:02:03:04:05:06")
        iface.setDescription("Some description")
        iface.setOwned(True)
        iface.addHostname("www.test.com")
        iface.setIPv4({
            "address": "192.168.10.168",
            "mask": "255.255.255.0",
            "gateway": "192.168.10.1",
            "DNS": "192.168.10.1"
        })
        iface.setPortsOpened(2)
        iface.setPortsClosed(3)
        iface.setPortsFiltered(4)
        host.addChild(iface.getID(), iface)
        self.mapper_manager.save(iface)

        h = self.mapper_manager.find(host.getID())
        self.assertEquals(
            len(h.getAllInterfaces()),
            len(host.getAllInterfaces()),
            "Interfaces from original host should be equals to retrieved host's interfaces")

        i = self.mapper_manager.find(h.getAllInterfaces()[0].getID())
        self.assertEquals(
            i.getID(),
            iface.getID(),
            "Interface's id' from original host should be equals to retrieved host's interface's id")

    def test_load_not_loaded_composite_host(self):
        # add host
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)
        # add inteface
        iface = Interface(name="192.168.10.168", mac="01:02:03:04:05:06")
        iface.setDescription("Some description")
        iface.setOwned(True)
        iface.addHostname("www.test.com")
        iface.setIPv4({
            "address": "192.168.10.168",
            "mask": "255.255.255.0",
            "gateway": "192.168.10.1",
            "DNS": "192.168.10.1"
        })
        iface.setPortsOpened(2)
        iface.setPortsClosed(3)
        iface.setPortsFiltered(4)
        host.addChild(iface.getID(), iface)
        self.mapper_manager.save(iface)

        #create a set of mappers, so we have a clean map
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(self.connector)

        h = self.mapper_manager.find(host.getID())
        self.assertEquals(
            len(h.getAllInterfaces()),
            len(host.getAllInterfaces()),
            "Interfaces from original host should be equals to retrieved host's interfaces")

        i = self.mapper_manager.find(h.getAllInterfaces()[0].getID())
        self.assertEquals(
            i.getID(),
            iface.getID(),
            "Interface's id' from original host should be equals to retrieved host's interface's id")


class MapperWithFileSystemManagerInegrationTest(unittest.TestCase):
    def setUp(self):
        self.db_name = self.new_random_workspace_name()

        self.fsmanager = FileSystemManager()

        self.connector = self.fsmanager.createDb(self.db_name)
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(self.connector)

    def new_random_workspace_name(self):
        return ("aworkspace" + "".join(random.sample(
            [chr(i) for i in range(65, 90)], 10))).lower()

    def tearDown(self):
        self.fsmanager.deleteDb(self.db_name)

    def test_host_saving(self):
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)

        self.assertNotEquals(
            self.connector.getDocument(host.getID()),
            None,
            "Document shouldn't be None")

        self.assertEquals(
            self.connector.getDocument(host.getID()).get("name"),
            host.getName(),
            "Document should have the same host name")

    def test_load_nonexistent_host_using_manager_find(self):
        self.assertEquals(
            self.connector.getDocument("1234"),
            None,
            "Nonexistent host should return None document")

        self.assertEquals(
            self.mapper_manager.find("1234"),
            None,
            "Nonexistent host should return None object")

    def test_load_nonexistent_host_using_mapper_find(self):
        self.assertEquals(
            self.connector.getDocument("1234"),
            None,
            "Nonexistent host should return None document")

        self.assertEquals(
            self.mapper_manager.getMapper(Host.__name__).find("1234"),
            None,
            "Nonexistent host should return None object")

    def test_find_not_loaded_host(self):
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)

        #create a set of mappers, so we have a clean map
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(self.connector)

        h = self.mapper_manager.find(host.getID())
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
        host = Host(name="coquito")
        self.mapper_manager.save(host)
        h_id = host.getID()

        self.assertNotEquals(
            self.mapper_manager.find(h_id),
            None,
            "Host should be in the mapper")

        self.assertNotEquals(
            self.connector.getDocument(h_id),
            None,
            "Host should be in the db")

        self.mapper_manager.remove(h_id)

        self.assertEquals(
            self.mapper_manager.find(h_id),
            None,
            "Host shouldn't exist anymore in the mapper")

        self.assertEquals(
            self.connector.getDocument(h_id),
            None,
            "Host shouldn't exist anymore in the db")

    def test_composite_host(self):
        # add host
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)
        # add inteface
        iface = Interface(name="192.168.10.168", mac="01:02:03:04:05:06")
        iface.setDescription("Some description")
        iface.setOwned(True)
        iface.addHostname("www.test.com")
        iface.setIPv4({
            "address": "192.168.10.168",
            "mask": "255.255.255.0",
            "gateway": "192.168.10.1",
            "DNS": "192.168.10.1"
        })
        iface.setPortsOpened(2)
        iface.setPortsClosed(3)
        iface.setPortsFiltered(4)
        host.addChild(iface.getID(), iface)
        self.mapper_manager.save(iface)

        h = self.mapper_manager.find(host.getID())
        self.assertEquals(
            len(h.getAllInterfaces()),
            len(host.getAllInterfaces()),
            "Interfaces from original host should be equals to retrieved host's interfaces")

        i = self.mapper_manager.find(h.getAllInterfaces()[0].getID())
        self.assertEquals(
            i.getID(),
            iface.getID(),
            "Interface's id' from original host should be equals to retrieved host's interface's id")

    def test_load_not_loaded_composite_host(self):
        # add host
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)
        # add inteface
        iface = Interface(name="192.168.10.168", mac="01:02:03:04:05:06")
        iface.setDescription("Some description")
        iface.setOwned(True)
        iface.addHostname("www.test.com")
        iface.setIPv4({
            "address": "192.168.10.168",
            "mask": "255.255.255.0",
            "gateway": "192.168.10.1",
            "DNS": "192.168.10.1"
        })
        iface.setPortsOpened(2)
        iface.setPortsClosed(3)
        iface.setPortsFiltered(4)
        host.addChild(iface.getID(), iface)
        self.mapper_manager.save(iface)

        #create a set of mappers, so we have a clean map
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(self.connector)

        h = self.mapper_manager.find(host.getID())
        self.assertEquals(
            len(h.getAllInterfaces()),
            len(host.getAllInterfaces()),
            "Interfaces from original host should be equals to retrieved host's interfaces")

        i = self.mapper_manager.find(h.getAllInterfaces()[0].getID())
        self.assertEquals(
            i.getID(),
            iface.getID(),
            "Interface's id' from original host should be equals to retrieved host's interface's id")


if __name__ == '__main__':
    unittest.main()
