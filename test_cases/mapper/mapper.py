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
from time import time
sys.path.append(os.path.abspath(os.getcwd()))

from mockito import mock, when, any

from model.hosts import Host, Interface, Service
from model.workspace import Workspace
from persistence.mappers.abstract_mapper import NullPersistenceManager
from managers.mapper_manager import MapperManager

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class HostMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(NullPersistenceManager())
        self.hmapper = self.mapper_manager.getMapper(Host.__name__)

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

        when(self.hmapper.pmanager).getDocument("1234").thenReturn(doc)

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

    def test_load_rubbish_host_doc(self):
        # we need to mock the persistence manager first,
        # so we can return an erroneous simulated doc
        doc = {
            "type": "RUBBISH",
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
        when(pmanager).getDocument(any(str)).thenReturn(doc)
        self.hmapper.setPersistenceManager(pmanager)

        host = self.hmapper.find("1234")
        self.assertEquals(
            host,
            None,
            "Doc is malformed so we should get None")

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
            self.hmapper.find(h_id),
            None,
            "Host shouldn't exist anymore")


class InterfaceMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(NullPersistenceManager())
        self.imapper = self.mapper_manager.getMapper(Interface.__name__)

    def tearDown(self):
        pass

    def test_interface_serialization(self):
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
        when(self.imapper.pmanager).getDocument("1234").thenReturn(doc)

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
            self.imapper.find(i_id),
            None,
            "Inteface shouldn't exist anymore")


class ServiceMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(NullPersistenceManager())
        self.smapper = self.mapper_manager.getMapper(Service.__name__)

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
        when(self.smapper.pmanager).getDocument("1234").thenReturn(doc)

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
            self.smapper.find(s_id),
            None,
            "Service shouldn't exist anymore")


class WorkspaceMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(NullPersistenceManager())
        self.wmapper = self.mapper_manager.getMapper(Workspace.__name__)

    def tearDown(self):
        pass

    def test_workspace_serialization(self):
        workspace = Workspace(name="workspace_test")
        workspace.setDescription("Some description")
        workspace.setCustomer("Infobyte")
        wserialized = self.wmapper.serialize(workspace)
        # if serialization fails, returns None
        self.assertNotEqual(
            wserialized,
            None,
            "Serialized workspace shouldn't be None")
        # we check the host attributes
        self.assertEquals(
            wserialized.get("_id"),
            workspace.getID(),
            "Serialized ID is not the same as workspace ID")
        self.assertEquals(
            wserialized.get("name"),
            workspace.getName(),
            "Serialized name is not the same as workspace name")
        self.assertEquals(
            wserialized.get("description"),
            workspace.getDescription(),
            "Serialized description is not the same as workspace description")
        self.assertEquals(
            wserialized.get("customer"),
            workspace.getCustomer(),
            "Serialized customer is not the same as workspace customer")

    def test_workspace_creation(self):
        workspace = Workspace(name="workspace_test")
        self.wmapper.save(workspace)
        w = self.wmapper.find(workspace.getID())
        self.assertEquals(
            w,
            workspace,
            "Workspace retrieved should be the same as persisted")
        self.assertEquals(
            w.getID(),
            workspace.getID(),
            "Workspace retrieved's Id should be the same as persisted's Id")

    def test_load_nonexistent_workspace(self):
        self.assertEquals(
            self.wmapper.load("Nonexistent"),
            None,
            "Nonexistent workspace should return None")

    def test_find_not_loaded_workspace(self):
        # we need to mock the persistence manager first,
        # so we can return a simulated doc
        doc = {
            "type": "Workspace",
            "_id": "workspace_test",
            "name": "workspace_test",
            "description": "some description",
            "customer": "Infobyte",
            "sdate": time(),
            "fdate": time()
        }
        when(self.wmapper.pmanager).getDocument("workspace_test").thenReturn(doc)

        workspace = self.wmapper.find("workspace_test")
        self.assertNotEquals(
            workspace,
            None,
            "Existent workspace shouldn't return None")

        self.assertEquals(
            workspace.getName(),
            "workspace_test",
            "Workspace name should be workspace_test")

        self.assertEquals(
            workspace.getCustomer(),
            "Infobyte",
            "Host os should be Infobyte")

    def test_workspace_create_and_delete(self):
        workspace = Workspace(name="workspace_test")
        self.wmapper.save(workspace)
        w_id = workspace.getID()

        self.assertNotEquals(
            self.wmapper.load(w_id),
            None,
            "Workspace should be saved")

        self.wmapper.delete(w_id)

        self.assertEquals(
            self.wmapper.find(w_id),
            None,
            "Workspace shouldn't exist anymore")


class MapperManagerTestSuite(unittest.TestCase):
    def setUp(self):
        self.mapper_manager = MapperManager()

    def tearDown(self):
        pass

    def test_create_and_retrieve_host(self):
        self.mapper_manager.createMappers(NullPersistenceManager())
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        self.mapper_manager.save(host)

        h = self.mapper_manager.find(host.getID())

        self.assertNotEquals(
            h,
            None,
            "Host retrieved shouldn't be None")

        self.assertEquals(
            host,
            h,
            "Host created should be the same as host retrieved")


class CompositeMapperTestSuite(unittest.TestCase):
    def setUp(self):
        self.mapper_manager = MapperManager()
        self.mapper_manager.createMappers(NullPersistenceManager())

    def tearDown(self):
        pass

    def create_host(self):
        host = Host(name="pepito", os="linux")
        host.setDescription("Some description")
        host.setOwned(True)
        return host

    def create_interface(self):
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
        return iface

    def test_find_composite_host(self):
        '''
        We are going to create a host, then save it.
        Next we create an interface and then add it
        to the host, and finally save it.
        '''
        # add host
        host = self.create_host()
        self.mapper_manager.save(host)
        # add inteface
        interface = self.create_interface()
        host.addChild(interface)
        self.mapper_manager.save(interface)

        h = self.mapper_manager.find(host.getID())
        self.assertEquals(
            h.getAllInterfaces(),
            host.getAllInterfaces(),
            "Interfaces from original host should be equals to retrieved host's interfaces")

    def test_load_composite_one_host_one_interface(self):
        '''
        We are going to create a host, then save it.
        Next we create an interface and then add it
        to the host, and finally save it.
        '''

        doc_host = {
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

        doc_interface = {
            "type": "Interface",
            "_id": "5678",
            "name": "192.168.10.168",
            "owned": False,
            "parent": "1234",
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
        when(pmanager).getDocument("1234").thenReturn(doc_host)
        when(pmanager).getDocument("5678").thenReturn(doc_interface)
        when(pmanager).getDocsByFilter(any(str), None).thenReturn([])
        when(pmanager).getDocsByFilter("1234", None).thenReturn([{'_id': "5678", 'type': "Interface"}])
        self.mapper_manager.createMappers(pmanager)

        host = self.mapper_manager.find("1234")
        self.assertNotEquals(
            host,
            None,
            "Existent host shouldn't be None")

        self.assertEquals(
            len(host.getAllInterfaces()),
            1,
            "Host should have one interface")

        iface = self.mapper_manager.find("5678")
        self.assertNotEquals(
            iface,
            None,
            "Existent interface shouldn't be None")

        self.assertEquals(
            host.getInterface("5678"),
            iface,
            "Interface inside host should be equals to retrieved interface")

        self.assertEquals(
            iface.getParent(),
            host,
            "Host should be the interface's parent")

    def test_load_composite_one_host_two_interfaces(self):

        doc_host = {
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

        doc_interface1 = {
            "type": "Interface",
            "_id": "5678",
            "name": "192.168.10.168",
            "owned": False,
            "parent": "1234",
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

        doc_interface2 = {
            "type": "Interface",
            "_id": "6789",
            "name": "192.168.10.168",
            "owned": False,
            "parent": "1234",
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
        when(pmanager).getDocument("1234").thenReturn(doc_host)
        when(pmanager).getDocument("5678").thenReturn(doc_interface1)
        when(pmanager).getDocument("6789").thenReturn(doc_interface2)
        when(pmanager).getDocsByFilter(any(str), None).thenReturn([])
        when(pmanager).getDocsByFilter("1234", None).thenReturn([{'_id': "5678", 'type': "Interface"}, {'_id': "6789", 'type': "Interface"}])
        self.mapper_manager.createMappers(pmanager)

        host = self.mapper_manager.find("1234")
        self.assertNotEquals(
            host,
            None,
            "Existent host shouldn't be None")

        self.assertEquals(
            len(host.getAllInterfaces()),
            2,
            "Host should have two interface")

        iface1 = self.mapper_manager.find("5678")
        self.assertNotEquals(
            iface1,
            None,
            "Existent interface1 shouldn't be None")

        self.assertEquals(
            host.getInterface("5678"),
            iface1,
            "Interface1 inside host should be equals to retrieved interface1")

        self.assertEquals(
            iface1.getParent(),
            host,
            "Host should be the interface1's parent")

        iface2 = self.mapper_manager.find("6789")
        self.assertNotEquals(
            iface2,
            None,
            "Existent interface2 shouldn't be None")

        self.assertEquals(
            host.getInterface("6789"),
            iface2,
            "Interface2 inside host should be equals to retrieved interface2")

        self.assertEquals(
            iface2.getParent(),
            host,
            "Host should be the interface2's parent")

    def test_load_composite_one_host_one_interface_two_services(self):

        doc_host = {
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

        doc_interface = {
            "type": "Interface",
            "_id": "5678",
            "name": "192.168.10.168",
            "owned": False,
            "parent": "1234",
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

        doc_service1 = {
            "type": "Service",
            "_id": "abcd",
            "name": "http",
            "owned": False,
            "parent": "5678",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "protocol": "tcp",
            "status": "open",
            "ports": [80],
            "version": "Apache 2.4"
        }

        doc_service2 = {
            "type": "Service",
            "_id": "efgh",
            "name": "ssh",
            "owned": False,
            "parent": "5678",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "protocol": "tcp",
            "status": "open",
            "ports": [22],
            "version": "OpenSSH"
        }

        pmanager = mock(NullPersistenceManager)
        when(pmanager).getDocument("1234").thenReturn(doc_host)
        when(pmanager).getDocument("5678").thenReturn(doc_interface)
        when(pmanager).getDocument("abcd").thenReturn(doc_service1)
        when(pmanager).getDocument("efgh").thenReturn(doc_service2)
        when(pmanager).getDocsByFilter(any(str), None).thenReturn([])
        when(pmanager).getDocsByFilter("1234", None).thenReturn([{'_id': "5678", 'type': "Interface"}])
        when(pmanager).getDocsByFilter("5678", None).thenReturn([{'_id': "abcd", 'type': "Service"}, {'_id': "efgh", 'type': "Service"}])
        self.mapper_manager.createMappers(pmanager)

        iface = self.mapper_manager.find("5678")
        self.assertNotEquals(
            iface,
            None,
            "Existent interface shouldn't be None")

        # Lets make sure that the host was created
        host = iface.getParent()
        self.assertEquals(
            host.getID(),
            "1234",
            "Interface's parent id should be 1234")

        self.assertEquals(
            host,
            self.mapper_manager.find("1234"),
            "Interface1's parent should be equals to the host retrieved")

        self.assertEquals(
            len(iface.getAllServices()),
            2,
            "Interface should have two services")

        services_ids = [srv.getID() for srv in iface.getAllServices()]
        self.assertIn(
            "abcd",
            services_ids,
            "Service 'abcd' should be one of the interface's services")

        self.assertIn(
            "efgh",
            services_ids,
            "Service 'efgh' should be one of the interface's services")

    def test_load_composite_one_host_one_note_one_vuln_one_credential(self):

        doc_host = {
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

        doc_note = {
            "type": "ModelObjectNote",
            "_id": "note1",
            "name": "Note1",
            "owned": False,
            "parent": "1234",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "text": "this is a note"
        }

        doc_vuln = {
            "type": "ModelObjectVuln",
            "_id": "vuln1",
            "name": "Vuln1",
            "owned": False,
            "parent": "1234",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "desc": "this is a vuln",
            "severity": "high",
            "refs": ["cve1", "cve2"]
        }

        doc_cred = {
            "type": "ModelObjectCred",
            "_id": "cred1",
            "name": "Vuln1",
            "owned": False,
            "parent": "1234",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "username": "infobyte",
            "password": "secret"
        }

        pmanager = mock(NullPersistenceManager)
        when(pmanager).getDocument("1234").thenReturn(doc_host)
        when(pmanager).getDocument("note1").thenReturn(doc_note)
        when(pmanager).getDocument("vuln1").thenReturn(doc_vuln)
        when(pmanager).getDocument("cred1").thenReturn(doc_cred)
        when(pmanager).getDocsByFilter(any(str), None).thenReturn([])
        when(pmanager).getDocsByFilter("1234", None).thenReturn(
            [{'_id': "note1", 'type': "ModelObjectNote"},
             {'_id': "vuln1", 'type': "ModelObjectVuln"},
             {'_id': "cred1", 'type': "ModelObjectCred"}])

        self.mapper_manager.createMappers(pmanager)

        host = self.mapper_manager.find("1234")
        self.assertNotEquals(
            host,
            None,
            "Existent host shouldn't be None")

        self.assertEquals(
            len(host.getNotes()),
            1,
            "Host should have one note")


        self.assertEquals(
            len(host.getVulns()),
            1,
            "Host should have one vuln")

        self.assertEquals(
            len(host.getCreds()),
            1,
            "Host should have one cred")

    def test_delete_interface_from_composite_one_host_one_interface_two_services(self): 
        doc_host = {
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

        doc_interface = {
            "type": "Interface",
            "_id": "5678",
            "name": "192.168.10.168",
            "owned": False,
            "parent": "1234",
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

        doc_service1 = {
            "type": "Service",
            "_id": "abcd",
            "name": "http",
            "owned": False,
            "parent": "5678",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "protocol": "tcp",
            "status": "open",
            "ports": [80],
            "version": "Apache 2.4"
        }

        doc_service2 = {
            "type": "Service",
            "_id": "efgh",
            "name": "ssh",
            "owned": False,
            "parent": "5678",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "protocol": "tcp",
            "status": "open",
            "ports": [22],
            "version": "OpenSSH"
        }

        self.pmanager = mock(NullPersistenceManager)
        when(self.pmanager).getDocument("1234").thenReturn(doc_host)
        when(self.pmanager).getDocument("5678").thenReturn(doc_interface)
        when(self.pmanager).getDocument("abcd").thenReturn(doc_service1)
        when(self.pmanager).getDocument("efgh").thenReturn(doc_service2)
        when(self.pmanager).getDocsByFilter(any(str), None).thenReturn([])
        when(self.pmanager).getDocsByFilter("1234", None).thenReturn([{'_id': "5678", 'type': "Interface"}])
        when(self.pmanager).getDocsByFilter("5678", None).thenReturn([{'_id': "abcd", 'type': "Service"}, {'_id': "efgh", 'type': "Service"}])

        self.mapper_manager.createMappers(self.pmanager)

        # load the host first
        host = self.mapper_manager.find("1234")

        #then remove the interface
        iface_id = host.getInterface("5678").getID()
        host.deleteChild(iface_id)

        def fake_remove(id):
            when(self.pmanager).getDocument(id).thenReturn(None)
        when(self.pmanager).remove("5678").thenReturn(fake_remove("5678"))
        when(self.pmanager).remove("abcd").thenReturn(fake_remove("abcd"))
        when(self.pmanager).remove("efgh").thenReturn(fake_remove("efgh"))
        self.mapper_manager.remove(iface_id)

        # now we make sure that we have removed the interface
        # and the services

        self.assertEquals(
            len(host.getAllInterfaces()),
            0,
            "Host should have no interfaces")

        self.assertEquals(
            self.mapper_manager.find("5678"),
            None,
            "Service abcd shouldn't exist anymore")


        self.assertEquals(
            self.mapper_manager.find("abcd"),
            None,
            "Service abcd shouldn't exist anymore")

        self.assertEquals(
            self.mapper_manager.find("efgh"),
            None,
            "Service efgh shouldn't exist anymore")

    def test_load_composite_one_workspace_two_hosts(self):

        doc_ws = {
            "type": "Workspace",
            "_id": "test_ws",
            "name": "test_ws",
            "description": "some description",
            "customer": "Infobyte",
            "sdate": None,
            "fdate": None
        }

        doc_host1 = {
            "type": "Host",
            "_id": "1234",
            "name": "pepito",
            "owned": False,
            "parent": "test_ws",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "os": "linux",
            "default_gateway": None
        }

        doc_host2 = {
            "type": "Host",
            "_id": "5678",
            "name": "coquito",
            "owned": False,
            "parent": "test_ws",
            "owner": None,
            "description": "some description",
            "metadata": None,
            "os": "windows",
            "default_gateway": None
        }

        pmanager = NullPersistenceManager()
        when(pmanager).getDocument("test_ws").thenReturn(doc_ws)
        when(pmanager).getDocument("1234").thenReturn(doc_host1)
        when(pmanager).getDocument("5678").thenReturn(doc_host2)
        when(pmanager).getDocsByFilter(any, any).thenReturn([])
        when(pmanager).getDocsByFilter(any(str), None).thenReturn([])
        when(pmanager).getDocsByFilter(None, None).thenReturn([])
        when(pmanager).getDocsByFilter("test_ws", None).thenReturn(
            [{'_id': "1234", 'type': "Host"},
             {'_id': "5678", 'type': "Host"}])
        #when(pmanager).getDocsByFilter(None, "Host").thenReturn([])

        self.mapper_manager.createMappers(pmanager)

        ws = self.mapper_manager.find("test_ws")
        self.assertNotEquals(
            ws,
            None,
            "Existent Workspace shouldn't be None")

        self.assertEquals(
            len(ws.getHosts()),
            2,
            "Workspace should have two hosts")

        hosts_ids = [host.getID() for host in ws.getHosts()]
        self.assertIn(
            "1234",
            hosts_ids,
            "Host '1234' should be one of the workspace's hosts")

        self.assertIn(
            "5678",
            hosts_ids,
            "Host '5678' should be one of the workspace's hosts")


if __name__ == '__main__':
    unittest.main()
