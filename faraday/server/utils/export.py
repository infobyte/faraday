import re
import csv
from io import StringIO, BytesIO
import logging

from faraday.server.models import (
    db,
    Comment
)

logger = logging.getLogger(__name__)


def export_vulns_to_csv(hosts, services, vulns, custom_fields_columns=None):
    buffer = StringIO()

    # Hosts
    host_headers = [
        "host_id", "ip", "hostnames", "host_description", "os", "mac",
        "host_owned", "host_creator_id", "obj_type"
    ]
    writer = csv.DictWriter(buffer, fieldnames=host_headers)
    writer.writeheader()

    for host in hosts:
        host_data = {
            "host_id": host.id,
            "ip": host.ip,
            "hostnames": [hostname.name for hostname in host.hostnames],
            "host_description": host.description,
            "os": host.os,
            "mac": host.mac,
            "host_owned": host.owned,
            "host_creator_id": host.creator_id,
            "obj_type": "host"
        }
        writer.writerow(host_data)
    writer.writerow({})

    # Services
    service_headers = [
        "service_id", "service_name", "service_description", "service_owned",
        "port", "protocol", "summary", "version", "service_status",
        "service_creator_id", "obj_type", "parent_id"
    ]
    writer = csv.DictWriter(buffer, fieldnames=service_headers)
    writer.writeheader()

    for service in services:
        service_data = {
            "service_id": service.id,
            "service_name": service.name,
            "service_description": service.description,
            "service_owned": service.owned,
            "port": service.port,
            "protocol": service.protocol,
            "summary": service.summary,
            "version": service.version,
            "service_status": service.status,
            "service_creator_id": service.creator_id,
            "parent_id": service.host_id,
            "obj_type": "service"
        }
        writer.writerow(service_data)
    writer.writerow({})

    # Vulnerabilities
    if custom_fields_columns is None:
        custom_fields_columns = []
    vuln_headers = [
        "confirmed", "vuln_id", "date", "vuln_name", "severity", "service",
        "target", "vuln_desc", "vuln_status", "hostnames", "comments",
        "vuln_owner", "os", "resolution", "refs", "easeofresolution",
        "web_vulnerability", "data", "website", "path", "status_code",
        "request", "response", "method", "params", "pname", "query",
        "policyviolations", "external_id", "impact_confidentiality",
        "impact_integrity", "impact_availability", "impact_accountability",
        "vuln_creator", "obj_type", "parent_id", "parent_type"
    ]
    vuln_headers += custom_fields_columns
    writer = csv.DictWriter(buffer, fieldnames=vuln_headers)
    writer.writeheader()

    for vuln in vulns:
        vuln_data = _build_vuln_data(vuln, custom_fields_columns)
        writer.writerow(vuln_data)

    memory_file = BytesIO()
    memory_file.write(buffer.getvalue().encode('utf8'))
    memory_file.seek(0)
    return memory_file


def _build_vuln_data(vuln, custom_fields_columns):
    comments_list = []
    comments = db.session.query(Comment).filter_by(
        object_type='vulnerability',
        object_id=vuln['_id']).all()
    for comment in comments:
        comments_list.append(comment.text)
    vuln_description = re.sub(' +', ' ', vuln['description'].strip().replace("\n", ""))
    vuln_date = vuln['metadata']['create_time']
    if vuln['service']:
        service_fields = ["status", "protocol", "name", "summary", "version", "ports"]
        service_fields_values = ["%s:%s" % (field, vuln['service'][field]) for field in service_fields]
        vuln_service = " - ".join(service_fields_values)
    else:
        vuln_service = ""
    if all(isinstance(hostname, str) for hostname in vuln['hostnames']):
        vuln_hostnames = vuln['hostnames']
    else:
        vuln_hostnames = [str(hostname['name']) for hostname in vuln['hostnames']]

    vuln_data = {"confirmed": vuln['confirmed'],
                    "vuln_id": vuln.get('_id', None),
                    "date": vuln_date,
                    "severity": vuln.get('severity', None),
                    "target": vuln.get('target', None),
                    "vuln_status": vuln.get('status', None),
                    "hostnames": vuln_hostnames,
                    "vuln_desc": vuln_description,
                    "vuln_name": vuln.get('name', None),
                    "service": vuln_service,
                    "comments": comments_list,
                    "vuln_owner": vuln.get('owner', None),
                    "os": vuln.get('host_os', None),
                    "resolution": vuln.get('resolution', None),
                    "refs": vuln.get('refs', None),
                    "easeofresolution": vuln.get('easeofresolution', None),
                    "data": vuln.get('data', None),
                    "website": vuln.get('website', None),
                    "path": vuln.get('path', None),
                    "status_code": vuln.get('status_code', None),
                    "request": vuln.get('request', None),
                    "response": vuln.get('response', None),
                    "method": vuln.get('method', None),
                    "params": vuln.get('params', None),
                    "pname": vuln.get('pname', None),
                    "query": vuln.get('query', None),
                    "policyviolations": vuln.get('policyviolations', None),
                    "external_id": vuln.get('external_id', None),
                    "impact_confidentiality": vuln["impact"]["confidentiality"],
                    "impact_integrity": vuln["impact"]["integrity"],
                    "impact_availability": vuln["impact"]["availability"],
                    "impact_accountability": vuln["impact"]["accountability"],
                    "web_vulnerability": vuln['type'] == "VulnerabilityWeb",
                    "vuln_creator": vuln["metadata"].get('creator', None),
                    "obj_type": "vulnerability",
                    "parent_id": vuln.get('parent', None),
                    "parent_type": vuln.get('parent_type', None)
    }
    if vuln['custom_fields']:
        for field_name, value in vuln['custom_fields'].items():
            if field_name in custom_fields_columns:
                vuln_data.update({field_name: value})

    return vuln_data
