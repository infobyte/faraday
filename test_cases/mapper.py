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

from mockito import mock, when, any

from model.hosts import Host, Interface, Service
from persistence.mappers.data_mappers import HostMapper, InterfaceMapper, ServiceMapper
from persistence.mappers.abstract_mapper import NullPersistenceManager
from managers.all import CouchdbManager

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class HostMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.hmapper = HostMapper()

    def tearDown(self):
        pass

    def test_host_serialization(self):
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        hserialized = self.hmapper.serialize(host)
        # if serialization fails, returns None
        self.assertNotEqual(
            hserialized,
            None,
            "Serialized host shouldn't be None")
        # we check the host attributes
        self.assertEquals(
            hserialized.get("_id"),
            host.getID(),
            "Serialized ID is not the same as Host ID")
        self.assertEquals(
            hserialized.get("name"),
            host.getName(),
            "Serialized name is not the same as Host name")
        self.assertEquals(
            hserialized.get("os"),
            host.getOS(),
            "Serialized OS is not the same as Host OS")
        self.assertEquals(
            hserialized.get("description"),
            host.getDescription(),
            "Serialized description is not the same as Host description")
        self.assertEquals(
            hserialized.get("owned"),
            host.isOwned(),
            "Serialized owned flag is not the same as Host owned flag")

    def test_host_creation(self):
        host = Host(name="pepito", os="linux")
        self.hmapper.save(host)
        h = self.hmapper.find(host.getID())
        self.assertEquals(
            h,
            host,
            "Host retrieved should be the same as persisted")
        self.assertEquals(
            h.getID(),
            host.getID(),
            "Host retrieved's Id should be the same as persisted's Id")

    def test_load_nonexistent_host(self):
        self.assertEquals(
            self.hmapper.load("1234"),
            None,
            "Nonexistent host should return None")

    def test_find_not_loaded_host(self):
        # we need to mock the persistence manager first,
        # so we can return a simulated doc
        doc = {
            "type": "Host",
            "_id": "1234",
            "name": "pepito",
            "owned": False,
            "parent": None,
            "owner": None,
            "description": "some description",
            "metadata": None,
            "os": "linux",
            "default_gateway": None
        }
        pmanager = mock(NullPersistenceManager)
        when(pmanager).get(any(str), any(str)).thenReturn(doc)
        self.hmapper.setPersistenceManager(pmanager)

        host = self.hmapper.find("1234")
        self.assertNotEquals(
            host,
            None,
            "Existent host shouldn't return None")

        self.assertEquals(
            host.getName(),
            "pepito",
            "Host name should be pepito")

        self.assertEquals(
            host.getOS(),
            "linux",
            "Host os should be linux")

    def test_host_create_and_delete(self):
        host = Host(name="pepito", os="linux")
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


class InterfaceMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.imapper = InterfaceMapper()

    def tearDown(self):
        pass

    def test_interface_serialization(self):
        iface = Interface(name="192.168.10.168", mac="01:02:03:04:05:06")
        iface.setDescription("Some description")
        iface.setOwned(True)
        iface.setNetworkSegment(None)
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
        iserialized = self.imapper.serialize(iface)
        # if serialization fails, returns None
        self.assertNotEqual(
            iserialized,
            None,
            "Serialized interface shouldn't be None")
        # we check the host attributes
        self.assertEquals(
            iserialized.get("_id"),
            iface.getID(),
            "Serialized ID is not the same as Interface ID")
        self.assertEquals(
            iserialized.get("name"),
            iface.getName(),
            "Serialized name is not the same as Interface name")
        self.assertEquals(
            iserialized.get("mac"),
            iface.getMAC(),
            "Serialized MAC is not the same as Interface MAC")
        self.assertEquals(
            iserialized.get("network_segment"),
            iface.getNetworkSegment(),
            "Serialized Network Segment is not the same as Interface Network Segment")
        self.assertEquals(
            iserialized.get("description"),
            iface.getDescription(),
            "Serialized description is not the same as Interface description")
        self.assertEquals(
            iserialized.get("owned"),
            iface.isOwned(),
            "Serialized owned flag is not the same as Interface owned flag")

    def test_interface_creation(self):
        iface = Interface(name="192.168.10.168", mac="01:02:03:04:05:06")
        iface.setDescription("Some description")
        iface.setOwned(True)
        iface.setNetworkSegment(None)
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

        self.imapper.save(iface)
        i = self.imapper.find(iface.getID())
        self.assertEquals(
            i,
            iface,
            "Interface retrieved should be the same as persisted")
        self.assertEquals(
            i.getID(),
            iface.getID(),
            "Interface retrieved's Id should be the same as persisted's Id")

    def test_load_nonexistent_interface(self):
        self.assertEquals(
            self.imapper.load("1234"),
            None,
            "Nonexistent interface should return None")

    def test_find_not_loaded_interface(self):
        # we need to mock the persistence manager first,
        # so we can return a simulated doc
        doc = {
            "type": "Interface",
            "_id": "1234",
            "name": "192.168.10.168",
            "owned": False,
            "parent": None,
            "owner": None,
            "description": "some description",
            "metadata": None,
            "mac": "01:02:03:04:05:06",
            "network_segment": None,
            "hostnames": ["www.test.com"],
            "ipv4": {
                "address": "192.168.10.168",
                "mask": "255.255.255.0",
                "gateway": "192.168.10.1",
                "DNS": "192.168.10.1"
            },
            "ipv6": {},
            "ports": {
                "opened": 2,
                "closed": 3,
                "filtered": 4,
            }
        }
        pmanager = mock(NullPersistenceManager)
        when(pmanager).get(any(str), any(str)).thenReturn(doc)
        self.imapper.setPersistenceManager(pmanager)

        iface = self.imapper.find("1234")
        self.assertNotEquals(
            iface,
            None,
            "Existent interface shouldn't return None")

        self.assertEquals(
            iface.getName(),
            "192.168.10.168",
            "Inteface name should be 192.168.10.168")

        self.assertEquals(
            iface.getMAC(),
            "01:02:03:04:05:06",
            "Interface MAC should be 01:02:03:04:05:06")

    def test_interface_create_and_delete(self):
        iface = Interface(name="192.168.10.168", mac="01:02:03:04:05:06")
        self.imapper.save(iface)
        i_id = iface.getID()

        self.assertNotEquals(
            self.imapper.load(i_id),
            None,
            "Inteface should be saved")

        self.imapper.delete(i_id)

        self.assertEquals(
            self.imapper.load(i_id),
            None,
            "Inteface shouldn't exist anymore")


class ServiceMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.smapper = ServiceMapper()

    def tearDown(self):
        pass

    def test_service_serialization(self):
        srv = Service(name="http")
        srv.setDescription("Some description")
        srv.setOwned(True)
        srv.setProtocol("tcp")
        srv.setPorts(80)
        srv.setStatus("open")
        srv.setVersion("Apache 2.4")
        sserialized = self.smapper.serialize(srv)
        # if serialization fails, returns None
        self.assertNotEqual(
            sserialized,
            None,
            "Serialized service shouldn't be None")
        # we check the host attributes
        self.assertEquals(
            sserialized.get("_id"),
            srv.getID(),
            "Serialized ID is not the same as Service ID")
        self.assertEquals(
            sserialized.get("name"),
            srv.getName(),
            "Serialized name is not the same as Service name")
        self.assertEquals(
            sserialized.get("protocol"),
            srv.getProtocol(),
            "Serialized protocol is not the same as Service protocol")
        self.assertEquals(
            sserialized.get("status"),
            srv.getStatus(),
            "Serialized status is not the same as Service status")
        self.assertEquals(
            sserialized.get("ports"),
            srv.getPorts(),
            "Serialized ports is not the same as Service ports")
        self.assertEquals(
            sserialized.get("description"),
            srv.getDescription(),
            "Serialized description is not the same as Interface description")
        self.assertEquals(
            sserialized.get("owned"),
            srv.isOwned(),
            "Serialized owned flag is not the same as Interface owned flag")

    def test_service_creation(self):
        srv = Service(name="http")
        srv.setDescription("Some description")
        srv.setOwned(True)
        srv.setProtocol("tcp")
        srv.setPorts(80)
        srv.setStatus("open")
        srv.setVersion("Apache 2.4")

        self.smapper.save(srv)
        s = self.smapper.find(srv.getID())
        self.assertEquals(
            s,
            srv,
            "Service retrieved should be the same as persisted")
        self.assertEquals(
            s.getID(),
            srv.getID(),
            "Service retrieved's Id should be the same as persisted's Id")

    def test_load_nonexistent_service(self):
        self.assertEquals(
            self.smapper.load("1234"),
            None,
            "Nonexistent service should return None")

    def test_find_not_loaded_service(self):
        # we need to mock the persistence manager first,
        # so we can return a simulated doc
        doc = {
            "type": "Service",
            "_id": "1234",
            "name": "http",
            "owned": False,
            "parent": None,
            "owner": None,
            "description": "some description",
            "metadata": None,
            "protocol": "tcp",
            "status": "open",
            "ports": [80],
            "version": "Apache 2.4"
        }
        pmanager = mock(NullPersistenceManager)
        when(pmanager).get(any(str), any(str)).thenReturn(doc)
        self.smapper.setPersistenceManager(pmanager)

        srv = self.smapper.find("1234")
        self.assertNotEquals(
            srv,
            None,
            "Existent service shouldn't return None")

        self.assertEquals(
            srv.getName(),
            "http",
            "Service name should be http")

        self.assertEquals(
            srv.getProtocol(),
            "tcp",
            "Service protocol should be tcp")

    def test_service_create_and_delete(self):
        srv = Service(name="http")
        self.smapper.save(srv)
        s_id = srv.getID()

        self.assertNotEquals(
            self.smapper.load(s_id),
            None,
            "Service should be saved")

        self.smapper.delete(s_id)

        self.assertEquals(
            self.smapper.load(s_id),
            None,
            "Service shouldn't exist anymore")


class MapperWithCouchPersistenceManagerInegrationTest(unittest.TestCase):
    def setUp(self):
        self.couchdbmanager = CouchdbManager(CONF.getCouchURI())
        self.hmapper = HostMapper()

    def tearDown(self):
        pass

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

        self.assertTrue(
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
        doc = {
            "type": "Host",
            "_id": "1234",
            "name": "pepito",
            "owned": False,
            "parent": None,
            "owner": None,
            "description": "some description",
            "metadata": None,
            "os": "linux",
            "default_gateway": None
        }
        self.couchdbmanager.saveDocument(doc)

        host = self.hmapper.find("1234")
        self.assertNotEquals(
            host,
            None,
            "Existent host shouldn't return None")

        self.assertEquals(
            host.getName(),
            "pepito",
            "Host name should be pepito")

        self.assertEquals(
            host.getOS(),
            "linux",
            "Host os should be linux")

    def test_service_create_and_delete(self):
        srv = Service(name="http")
        self.smapper.save(srv)
        s_id = srv.getID()

        self.assertNotEquals(
            self.smapper.load(s_id),
            None,
            "Service should be saved")

        self.smapper.delete(s_id)

        self.assertEquals(
            self.smapper.load(s_id),
            None,
            "Service shouldn't exist anymore")

if __name__ == '__main__':
    unittest.main()
