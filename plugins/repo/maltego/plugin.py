#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from __future__ import with_statement
from plugins import core

import zipfile
import sys
import re
import os

try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION

ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

current_path = os.path.abspath(os.getcwd())

__author__ = "Ezequiel Tavella"
__copyright__ = "Copyright (c) 2015, Infobyte LLC"
__credits__ = ["Ezequiel Tavella"]
__license__ = ""
__version__ = "1.0.1"
__maintainer__ = "Ezequiel Tavella"
__status__ = "Development"


def openMtgx(mtgx_file):

    try:
        file = zipfile.ZipFile(mtgx_file, "r")
        xml = ET.parse(file.open('Graphs/Graph1.graphml'))

    except:
        print "Bad report format"
        return None

    file.close()
    return xml


class Host():

    def __init__(self):
        self.ip = ""
        self.node_id = ""
        self.dns_name = ""
        self.website = ""
        self.netblock = ""
        self.location = ""
        self.mx_record = ""
        self.ns_record = ""


class MaltegoMtgxParser():

    def __init__(self, xml_file):

        self.xml = openMtgx(xml_file)

        self.nodes = self.xml.findall(
            "{http://graphml.graphdrawing.org/xmlns}graph/"
            "{http://graphml.graphdrawing.org/xmlns}node")

        self.edges = self.xml.findall(
            "{http://graphml.graphdrawing.org/xmlns}graph/"
            "{http://graphml.graphdrawing.org/xmlns}edge")

        self.list_hosts = []
        self.relations = {}

    def getRelations(self):
        """
        Get relations between nodes.
        Two ways: Source-> Target
        Source <- Target
        """
        for edge in self.edges:

            source = edge.get("source")
            target = edge.get("target")

            if source not in self.relations:
                self.relations.update({source: [target]})

            if target not in self.relations:
                self.relations.update({target: [source]})

            values = self.relations[source]
            values.append(target)
            self.relations.update({source: values})

            values = self.relations[target]
            values.append(source)
            self.relations.update({target: values})

    def getIpAndId(self, node):

        # Find node ID and maltego entity
        node_id = node.get("id")
        entity = node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity")

        # Check if is IPv4Address
        if entity.get("type") != "maltego.IPv4Address":
            return None

        # Get IP value
        value = entity.find(
            "{http://maltego.paterva.com/xml/mtgx}Properties/"
            "{http://maltego.paterva.com/xml/mtgx}Property/"
            "{http://maltego.paterva.com/xml/mtgx}Value")

        return {"node_id": node_id, "ip": value.text}

    def getNode(self, node_id):

        # Get node, filter by id
        for node in self.nodes:

            if node.get("id") == node_id:
                return node

    def getType(self, node):

        # Get type of this node
        entity = node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity")

        return entity.get("type")

    def getWebsite(self, target_node):

        # Parse Website Entity
        result = {"name": "", "ssl_enabled": "", "urls": ""}

        props = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties")

        for prop in props:

            name_property = prop.get("name")
            value = prop.find(
                "{http://maltego.paterva.com/xml/mtgx}Value").text

            if name_property == "fqdn":
                result["name"] = value
            elif name_property == "website.ssl-enabled":
                result["ssl_enabled"] = value
            elif name_property == "URLS":
                result["urls"] = value

        return result

    def getNetBlock(self, target_node):

        # Parse Netblock Entity
        result = {"ipv4_range": "", "network_owner": "", "country": ""}

        props = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties")

        for prop in props:

            name_property = prop.get("name")
            value = prop.find(
                "{http://maltego.paterva.com/xml/mtgx}Value").text

            if name_property == "ipv4-range":
                result["ipv4_range"] = value
            elif name_property == "description":
                result["network_owner"] = value
            elif name_property == "country":
                result["country"] = value

        return result

    def getLocation(self, target_node):

        # Parse Location Entity
        result = {
            "name": "",
            "area": "",
            "country_code": "",
            "longitude": "",
            "latitude": "",
            "area_2": ""}

        # Get relations with other nodes
        node_relations = self.relations[target_node.get("id")]

        # Find location node based in relation with netblock node.
        located = False
        for node_id in node_relations:

            target_node = self.getNode(node_id)
            if self.getType(target_node) == "maltego.Location":
                located = True
                break

        if not located:
            return None

        # Get properties and update data
        props = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties")

        for prop in props:

            name_property = prop.get("name")
            value = prop.find(
                "{http://maltego.paterva.com/xml/mtgx}Value").text

            if name_property == "location.name":
                result["name"] = value
            elif name_property == "location.area":
                result["area"] = value
            elif name_property == "countrycode":
                result["country_code"] = value
            elif name_property == "longitude":
                result["longitude"] = value
            elif name_property == "latitude":
                result["latitude"] = value
            elif name_property == "area":
                result["area_2"] = value

        return result

    def getValue(self, target_node):

        # Parse Entity
        result = {"value": ""}

        value = target_node.find(
            "{http://graphml.graphdrawing.org/xmlns}data/"
            "{http://maltego.paterva.com/xml/mtgx}MaltegoEntity/"
            "{http://maltego.paterva.com/xml/mtgx}Properties/"
            "{http://maltego.paterva.com/xml/mtgx}Property/"
            "{http://maltego.paterva.com/xml/mtgx}Value")

        result["value"] = value.text
        return result

    def parse(self):

        self.getRelations()

        for node in self.nodes:

            # Get IP Address if not continue with other node...
            result = self.getIpAndId(node)
            if not result:
                continue

            # Create host with values by default
            host = Host()
            host.ip = result["ip"]
            host.node_id = result["node_id"]

            # Get relations with other nodes
            node_relations = self.relations[host.node_id]

            for node_id in node_relations:

                # Get target node and type of node.
                target_node = self.getNode(node_id)
                target_type = self.getType(target_node)

                # Check type of node y add data to host...
                if target_type == "maltego.DNSName":
                    host.dns_name = self.getValue(target_node)
                elif target_type == "maltego.Website":
                    host.website = self.getWebsite(target_node)
                elif target_type == "maltego.Netblock":
                    host.netblock = self.getNetBlock(target_node)
                    # Get location based in relation: netblock -> location
                    host.location = self.getLocation(target_node)
                elif target_type == "maltego.MXRecord":
                    host.mx_record = self.getValue(target_node)
                elif target_type == "maltego.NSRecord":
                    host.ns_record = self.getValue(target_node)

            self.list_hosts.append(host)

        return self.list_hosts


class MaltegoPlugin(core.PluginBase):

    def __init__(self):

        core.PluginBase.__init__(self)
        self.id = "Maltego"
        self.name = "Maltego MTGX Output Plugin"
        self.plugin_version = "1.0.1"
        self.version = "Maltego 3.6"
        self.framework_version = "1.0.0"
        self.current_path = None
        self.options = None
        self._current_output = None

        self._command_regex = re.compile(
            r'^(sudo maltego|maltego|\.\/maltego).*?')

        global current_path

    def parseOutputString(self, filename, debug=False):

        maltego_parser = MaltegoMtgxParser(filename)
        for host in maltego_parser.parse():
            # Create host
            try:
                old_hostname = host.dns_name["value"]
            except:
                old_hostname = "unknown"

            host_id = self.createAndAddHost(
                name=host.ip,
                old_hostname=old_hostname)

        # Create interface
        try:
            network_segment = host.netblock["ipv4_range"]
            hostname_resolution = [host.dns_name["value"]]
        except:
            network_segment = "unknown"
            hostname_resolution = "unknown"

        interface_id = self.createAndAddInterface(
            host_id=host_id,
            name=host.ip,
            ipv4_address=host.ip,
            network_segment=network_segment,
            hostname_resolution=hostname_resolution)

        # Create note with NetBlock information
        if host.netblock:
            try:
                text = (
                    "Network owner:\n" +
                    host.netblock["network_owner"] or "unknown" +
                    "Country:\n" + host.netblock["country"] or "unknown")
            except:
                text = "unknown"

            self.createAndAddNoteToHost(
                host_id=host_id,
                name="Netblock Information",
                text=text.encode('ascii', 'ignore')
            )

        # Create note with host location
        if host.location:
            try:
                text = (
                    "Location:\n" +
                    host.location["name"] +
                    "\nArea:\n" +
                    host.location["area"] +
                    "\nArea 2:\n" +
                    host.location["area_2"] +
                    "\nCountry_code:\n" +
                    host.location["country_code"] +
                    "\nLatitude:\n" +
                    host.location["latitude"] +
                    "\nLongitude:\n" +
                    host.location["longitude"])
            except:
                text = "unknown"

            self.createAndAddNoteToHost(
                host_id=host_id,
                name="Location Information",
                text=text.encode('ascii', 'ignore'))

        # Create service web server
        if host.website:
            try:
                description = "SSL Enabled: " + host.website["ssl_enabled"]
            except:
                description = "unknown"

            service_id = self.createAndAddServiceToInterface(
                host_id=host_id,
                interface_id=interface_id,
                name=host.website["name"],
                protocol="TCP:HTTP",
                ports=[80],
                description=description)

            try:
                text = "Urls:\n" + host.website["urls"]

                self.createAndAddNoteToService(
                    host_id=host_id,
                    service_id=service_id,
                    name="URLs",
                    text=text.encode('ascii', 'ignore'))
            except:
                pass

        if host.mx_record:

            self.createAndAddServiceToInterface(
                host_id=host_id,
                interface_id=interface_id,
                name=host.mx_record["value"],
                protocol="SMTP",
                ports=[25],
                description="E-mail Server")

        if host.ns_record:

            self.createAndAddServiceToInterface(
                host_id=host_id,
                interface_id=interface_id,
                name=host.ns_record["value"],
                protocol="DNS",
                ports=[53],
                description="DNS Server")

    def processReport(self, filepath):
        self.parseOutputString(filepath)

    def processCommandString(self, username, current_path, command_string):
        pass


def createPlugin():
    return MaltegoPlugin()
