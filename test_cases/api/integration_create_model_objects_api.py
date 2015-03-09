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
sys.path.append(os.path.abspath(os.getcwd()))

from model.controller import ModelController
from auth.manager import SecurityManager
from managers.mapper_manager import MapperManager
from managers.all import PluginManager
import apis.rest.api as restapi
from apis.rest.client import ModelRestApiClient

from model.hosts import Host, Interface, Service

from mockito import mock, when

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class CreationModelObjectsApiRest(unittest.TestCase):
    """
    This suite tests the interaction between the rest api server,
    the model controller, the factory and the rest api client.
    The client is going to be used by the plugins (through PluginBase).
    """
    def setUp(self):
        self._security_manager = mock(SecurityManager())
        self._mappers_manager = mock(MapperManager())
        self._plugin_manager = mock(PluginManager)

        self._model_controller = ModelController(
            self._security_manager,
            self._mappers_manager)

        restapi.startAPIs(
            self._plugin_manager, self._model_controller,
            self._mappers_manager)

        #TODO: load conf from file
        self.client = ModelRestApiClient("127.0.0.1", 9977)

    def tearDown(self):
        restapi.stopAPIs()

    def test_host_creation(self):
        name = "pepito"
        os = "Windows"
        host_id = self.client.createHost(name, os)
        host = Host(name, os)

        self.assertEquals(host.getID(), host_id, "ids should be the same")

    def test_interface_creation(self):
        name = "pepito"
        os = "Windows"
        host = Host(name, os)

        when(self._model_controller).find(host.getID()).thenReturn(host)

        name = ""
        mac = "00:00:00:00:00:00"
        ipv4_address = "0.0.0.0"
        ipv4_mask = "0.0.0.0"
        ipv4_gateway = "0.0.0.0"
        ipv4_dns = []
        ipv6_address = "0000:0000:0000:0000:0000:0000:0000:0000"
        ipv6_prefix = "00"
        ipv6_gateway = "0000:0000:0000:0000:0000:0000:0000:0000"
        ipv6_dns = []
        network_segment = ""
        hostname_resolution = []

        interface_id = self.client.createInterface(
            name, mac, ipv4_address, ipv4_mask, ipv4_gateway, ipv4_dns,
            ipv6_address, ipv6_prefix, ipv6_gateway, ipv6_dns, network_segment,
            hostname_resolution, host.getID())

        interface = Interface(
            name, mac, ipv4_address, ipv4_mask, ipv4_gateway, ipv4_dns,
            ipv6_address, ipv6_prefix, ipv6_gateway, ipv6_dns, network_segment,
            hostname_resolution, parent_id=host.getID())

        self.assertNotEquals(
            interface_id, None, "interface created shouldn't be None")

        self.assertEquals(
            interface.getID(), interface_id, "ids should be the same")

    def test_service_creation(self):
        name = "pepito"
        os = "Windows"
        host = Host(name, os)

        name = ""
        mac = "00:00:00:00:00:00"
        ipv4_address = "0.0.0.0"
        ipv4_mask = "0.0.0.0"
        ipv4_gateway = "0.0.0.0"
        ipv4_dns = []
        ipv6_address = "0000:0000:0000:0000:0000:0000:0000:0000"
        ipv6_prefix = "00"
        ipv6_gateway = "0000:0000:0000:0000:0000:0000:0000:0000"
        ipv6_dns = []
        network_segment = ""
        hostname_resolution = []

        interface = Interface(
            name, mac, ipv4_address, ipv4_mask, ipv4_gateway, ipv4_dns,
            ipv6_address, ipv6_prefix, ipv6_gateway, ipv6_dns, network_segment,
            hostname_resolution, parent_id=host.getID())

        when(self._model_controller).find(
            interface.getID()).thenReturn(interface)

        name = "srv"
        protocol = "tcp"
        ports = []
        status = "running"
        version = "unknown"
        description = ""

        service_id = self.client.createService(
            name, protocol, ports, status, version, description,
            interface.getID())

        service = Service(name, protocol, ports, status, version, description,
                          parent_id=interface.getID())

        self.assertNotEquals(
            service_id, None, "service created shouldn't be None")

        self.assertEquals(
            service.getID(), service_id, "ids should be the same")


if __name__ == '__main__':
    unittest.main()
