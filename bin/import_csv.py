#!/usr/bin/env python2.7

"""
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file "doc/LICENSE" for the license information
"""

import csv
from time import mktime
from datetime import datetime
from persistence.server import models

WORKSPACE = ""
__description__ = "Import Faraday objects from CSV file"
__prettyname__ = "Import objects from CSV"

VULN_SEVERITIES = ["info", "low", "med", "high", "critical"]
VULN_STATUS = ["opened", "closed", "re-opened", "risk-accepted"]
SERVICE_STATUS = ["open", "filtered", "close"]


def parse_register(register):

    host = parse_host(register)
    interface = parse_interface(register)
    service = parse_service(register)
    vulnerability = parse_vulnerability(register)
    vulnerability_web = parse_vulnerability_web(register)

    return host, interface, service, vulnerability, vulnerability_web


def transform_dict_to_object(columns, register):

    """
    Iterate over all columns and create a new obj with default data
    and values with the real key for Faraday objects.
    """

    obj = {}

    for key, val in columns.iteritems():

        # Default data
        value = {val : ""}

        if val == "owned" or val == "confirmed":
            value[val] = False

        elif val == "ports" or val == "hostnames" or val == "refs" or val == "policyviolations":
            value[val] = []

        elif key == "service_status":
            value[val] = "open"

        elif key == "vulnerability_status" or key == "vulnerability_web_status":
            value[val] = "opened"

        elif key == "vulnerability_severity" or key == "vulnerability_web_severity":
            value[val] = "info"

        # Copy data to new object
        if key in register:

            if val == "ports":
                value[val] = [register[key]]

            elif val == "owned" or val == "confirmed":
                if register[key] == "true":
                    value[val] = True

            elif val == "desc":
                value["description"] = register[key]
                value["desc"] = register[key]

            elif val == "refs" or val == "hostnames" or val == "policyviolations":
                value[val] = register[key].split(",")

            elif key == "service_status":
                if register[key].lower() in SERVICE_STATUS:
                    value[val] = register[key]

            elif key == "vulnerability_status" or key =="vulnerability_web_status":
                if register[key].lower() in VULN_STATUS:
                    value[val] = register[key]

            elif key == "vulnerability_severity" or key == "vulnerability_web_severity":
                if register[key].lower() in VULN_SEVERITIES:
                    value[val] = register[key]
            else:
                value[val] = register[key]

        # Append new value to new object.
        obj.update(value)

    # Check if obj is Invalid, return None
    for key, val in obj.iteritems():
        if val != [""] and val != [] and val != "" and val != False and val != "info" and val != "opened" and val != "open":
            return obj

    return None


def parse_host(register):

    columns = {
        "host_name" : "name",
        "host_description" : "description",
        "host_owned" : "owned", #boolean
        "host_os" : "os"
    }

    obj = transform_dict_to_object(columns, register)
    if obj is None:
        return None
    host = models.Host(obj, WORKSPACE)

    try:

        date = register.get("host_metadata_create_time")
        if date is not None:
            datetime_object = datetime.strptime(date, "%m/%d/%Y")
            host._metadata.create_time = mktime(datetime_object.timetuple())
    except Exception:
        print "Invalid date", host.name

    return host


def parse_interface(register):

    columns = {
        "interface_name" : "name",
        "interface_description" : "description",
        "interface_hostnames" : "hostnames", #list
        "interface_mac" : "mac",
        "interface_network_segment" : "network_segment",
        "interface_ipv4_address" : "ipv4_address",
        "interface_ipv4_gateway" : "ipv4_gateway",
        "interface_ipv4_mask" : "ipv4_mask",
        "interface_ipv4_dns" : "ipv4_dns",
        "interface_ipv6_address" : "ipv6_address",
        "interface_ipv6_gateway" : "ipv6_gateway",
        "interface_ipv6_prefix" : "ipv6_prefix",
        "interface_ipv6_dns" : "ipv6_dns"
    }

    obj = transform_dict_to_object(columns, register)
    if obj is None:
        return None
    interface = models.Interface(obj, WORKSPACE)
    return interface


def parse_service(register):

    columns = {
        "service_name" : "name",
        "service_description" : "description",
        "service_owned" : "owned", #boolean
        "service_port" : "ports", #list
        "service_protocol": "protocol",
        "service_version" : "version",
        "service_status" : "status"
    }

    obj = transform_dict_to_object(columns, register)
    if obj is None:
        return None
    service = models.Service(obj, WORKSPACE)
    return service


def parse_vulnerability(register):

    columns = {
        "vulnerability_name" : "name",
        "vulnerability_desc" : "desc",
        "vulnerability_data" : "data",
        "vulnerability_severity" : "severity",
        "vulnerability_refs" : "refs", #list
        "vulnerability_confirmed" : "confirmed", #boolean
        "vulnerability_resolution" : "resolution",
        "vulnerability_status" : "status",
        "vulnerability_policyviolations" : "policyviolations" #list

    }

    obj = transform_dict_to_object(columns, register)
    if obj is None:
        return None
    vulnerability = models.Vuln(obj, WORKSPACE)

    try:

        date = register.get("vulnerability_metadata_create_time")
        if date is not None:
            datetime_object = datetime.strptime(date, "%m/%d/%Y")
            vulnerability._metadata.create_time = mktime(datetime_object.timetuple())
    except Exception:
        print "Invalid date", vulnerability.name

    return vulnerability


def parse_vulnerability_web(register):

    columns = {
        "vulnerability_web_name" : "name",
        "vulnerability_web_desc" : "desc",
        "vulnerability_web_data" : "data",
        "vulnerability_web_severity" : "severity",
        "vulnerability_web_refs" : "refs", #list
        "vulnerability_web_confirmed" : "confirmed", #boolean
        "vulnerability_web_status" : "status",
        "vulnerability_web_website" : "website",
        "vulnerability_web_request" : "request",
        "vulnerability_web_response" : "response",
        "vulnerability_web_method" : "method",
        "vulnerability_web_pname" : "pname",
        "vulnerability_web_params" : "params",
        "vulnerability_web_query" : "query",
        "vulnerability_web_resolution" : "resolution",
        "vulnerability_web_policyviolations" : "policyviolations", #list
        "vulnerability_web_path" : "path"
    }

    obj = transform_dict_to_object(columns, register)
    if obj is None:
        return None
    vulnerability_web = models.VulnWeb(obj, WORKSPACE)

    try:
        date = register.get("vulnerability_web_metadata_create_time")
        if date is not None:
            datetime_object = datetime.strptime(date, "%m/%d/%Y")
            vulnerability_web._metadata.create_time = mktime(datetime_object.timetuple())
    except Exception:
        print "Invalid date", vulnerability_web.name

    return vulnerability_web


def main(workspace="", args=None, parser=None):

    WORKSPACE = workspace

    parser.add_argument("--csv", help="Csv file to import")
    parsed_args = parser.parse_args(args)

    if not parsed_args.csv:
        print "Error: Give a CSV file to import with --csv"
        return 2, None

    try:
        file_csv = open(parsed_args.csv, "r")
    except:
        print "Error: Unreadeable CSV file, check the path"
        raise

    counter = 0
    csv_reader = csv.DictReader(file_csv, delimiter=",", quotechar='"')
    for register in csv_reader:

        host, interface, service, vulnerability, vulnerability_web = parse_register(register)

        # Set all IDs and create objects
        if host is not None:

            host.setID(None)
            if not models.get_host(WORKSPACE, host.getID()):

                counter += 1
                print "New host: " + host.getName()
                models.create_host(WORKSPACE, host)

        if interface is not None:

            interface.setID(host.getID())
            if not models.get_interface(WORKSPACE, interface.getID()):

                counter += 1
                print "New interface: " + interface.getName()
                models.create_interface(WORKSPACE, interface)

        if service is not None:

            service.setID(interface.getID())
            if not models.get_service(WORKSPACE, service.getID()):

                counter += 1
                print "New service: " + service.getName()
                models.create_service(WORKSPACE, service)

        # Check if Service exist, then create the vuln with parent Service.
        # If not exist the Service, create the vuln with parent Host.
        if vulnerability is not None:

            if service is None:
                vulnerability.setID(host.getID())
            else:
                vulnerability.setID(service.getID())
            if not models.get_vuln(WORKSPACE, vulnerability.getID()):

                counter += 1
                print "New vulnerability: " + vulnerability.getName()
                models.create_vuln(WORKSPACE, vulnerability)

        elif vulnerability_web is not None:

            vulnerability_web.setID(service.getID())
            if not models.get_web_vuln(WORKSPACE, vulnerability_web.getID()):

                counter += 1
                print "New web vulnerability: " + vulnerability_web.getName()
                models.create_vuln_web(WORKSPACE, vulnerability_web)

    print "[*]", counter, "new Faraday objects created."
    file_csv.close()
    return 0, None
