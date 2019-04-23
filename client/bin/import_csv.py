#!/usr/bin/env python2.7

"""
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
See the file "doc/LICENSE" for the license information
"""

import csv
from time import mktime
from datetime import datetime
from faraday.client.persistence.server import models
from faraday.client.persistence.server.server_io_exceptions import ConflictInDatabase, CantCommunicateWithServerError

WORKSPACE = ""
__description__ = "Import Faraday objects from CSV file"
__prettyname__ = "Import objects from CSV"

VULN_SEVERITIES = ["info", "low", "med", "high", "critical"]
VULN_STATUS = ["opened", "closed", "re-opened", "risk-accepted"]
SERVICE_STATUS = ["open", "filtered", "close"]


def parse_register(register):

    host = parse_host(register)
    service = parse_service(register)
    vulnerability = parse_vulnerability(register)
    vulnerability_web = parse_vulnerability_web(register)

    return host, service, vulnerability, vulnerability_web


def transform_dict_to_object(columns, register):

    """
    Iterate over all columns and create a new obj with default data
    and values with the real key for Faraday objects.
    """

    obj = {}

    for key, val in columns.iteritems():

        # Default data
        value = {val : ""}

        if val == "service_id":
            value["parent"] = register["service_id"]

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

            if val == "host_name":
                value[val] = register['interface_ipv4_address'] or register['interface_ipv6_address']

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
                if register[key].lower() == 'informational':
                    register[key] = 'info'
                if register[key].lower() == 'medium':
                    register[key] = 'med'
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
        print("Invalid date", host.name)

    return host


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
        print("Invalid date", vulnerability.name)

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
        print("Invalid date", vulnerability_web.name)

    return vulnerability_web


def main(workspace="", args=None, parser=None):

    WORKSPACE = workspace

    parser.add_argument("--csv", help="Csv file to import")
    parsed_args = parser.parse_args(args)

    if not parsed_args.csv:
        print("Error: Give a CSV file to import with --csv")
        return 2, None

    try:
        file_csv = open(parsed_args.csv, "r")
    except:
        print("Error: Unreadeable CSV file, check the path")
        raise

    counter = 0
    csv_reader = csv.DictReader(file_csv, delimiter=",", quotechar='"')
    for register in csv_reader:
        try:
            host, service, vulnerability, vulnerability_web = parse_register(register)

            # Set all IDs and create objects
            if host is not None:
                old_host = models.get_host(WORKSPACE, ip=host.getName())
                if not old_host:

                    counter += 1

                    print("New host: " + host.getName())
                    try:
                        models.create_host(WORKSPACE, host)
                    except Exception as ex:
                        print(ex)
                host = models.get_host(WORKSPACE, ip=host.getName())

            if service is not None:
                service.setParent(host.getID())
                service_params = {
                    'name': service.getName(),
                    'port': service.getPorts()[0],
                    'protocol': service.getProtocol(),
                    'host_id': service.getParent()
                }
                old_service = models.get_service(WORKSPACE, **service_params)
                if not old_service:

                    counter += 1
                    print("New service: " + service.getName())
                    models.create_service(WORKSPACE, service)
                service = models.get_service(WORKSPACE, **service_params)

            # Check if Service exist, then create the vuln with parent Service.
            # If not exist the Service, create the vuln with parent Host.
            if vulnerability is not None:
                if host and not service:
                    parent_type = 'Host'
                    parent_id = host.getID()
                if host and service:
                    parent_type = 'Service'
                    parent_id = service.getID()
                vulnerability.setParent(parent_id)
                vulnerability.setParentType(parent_type)

                vuln_params = {
                    'name': vulnerability.getName(),
                    'description': vulnerability.getDescription(),
                    'parent_type': parent_type,
                    'parent': parent_id,
                }

                if not models.get_vuln(WORKSPACE, **vuln_params):
                    counter += 1
                    print("New vulnerability: " + vulnerability.getName())
                    models.create_vuln(WORKSPACE, vulnerability)

            elif vulnerability_web is not None:

                vuln_web_params = {
                    'name': vulnerability_web.getName(),
                    'description': vulnerability_web.getDescription(),
                    'parent': service.getID(),
                    'parent_type': 'Service',
                    'method': vulnerability_web.getMethod(),
                    'parameter_name': vulnerability_web.getParams(),
                    'path': vulnerability_web.getPath(),
                    'website': vulnerability_web.getWebsite(),
                }
                vulnerability_web.setParent(service.getID())
                if not models.get_web_vuln(WORKSPACE, **vuln_web_params):

                    counter += 1
                    print("New web vulnerability: " + vulnerability_web.getName())
                    models.create_vuln_web(WORKSPACE, vulnerability_web)
        except ConflictInDatabase:
            print('Conflict in Database, skiping csv row')
        except CantCommunicateWithServerError as ex:
            print(register)
            print('Error', ex)
    print("[*]", counter, "new Faraday objects created.")
    file_csv.close()
    return 0, None
