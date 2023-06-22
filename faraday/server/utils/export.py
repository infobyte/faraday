"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import csv
import logging
from io import StringIO, BytesIO

# Local application imports
from faraday.server.models import (
    db,
    Comment,
    Host,
    Service
)

logger = logging.getLogger(__name__)


def export_vulns_to_csv(vulns, custom_fields_columns=None):
    buffer = StringIO()

    vuln_headers = [
        "confirmed", "id", "date", "name", "severity", "service",
        "target", "desc", "status", "hostnames", "comments", "owner",
        "os", "resolution", "refs", "easeofresolution", "web_vulnerability",
        "data", "website", "path", "status_code", "request", "response", "method",
        "params", "pname", "query", "cve", "cvss2_vector_string", "cvss2_base_score",
        "cvss3_vector_string", "cvss3_base_score", "cwe", "policyviolations", "external_id",
        "impact_confidentiality", "impact_integrity", "impact_availability",
        "impact_accountability", "update_date"
    ]

    if custom_fields_columns is None:
        custom_fields_columns = []
    else:
        # Add 'cf_' prefix to custom fields name
        custom_fields_columns = ['cf_' + cf for cf in custom_fields_columns]
    vuln_headers += custom_fields_columns

    headers = vuln_headers + [
        "host_id", "host_description", "mac",
        "host_owned", "host_creator_id", "host_date", "host_update_date",
        "service_id", "service_name", "service_description", "service_owned",
        "port", "protocol", "summary", "version", "service_status",
        "service_creator_id", "service_date", "service_update_date", "service_parent_id"
    ]

    writer = csv.DictWriter(buffer, fieldnames=headers)
    writer.writeheader()

    comments_dict = {}
    hosts_ids = set()
    services_ids = set()
    vulns_ids = set()

    for vuln in vulns:
        if vuln['parent_type'] == 'Host':
            hosts_ids.add(vuln['parent'])
        elif vuln['parent_type'] == 'Service':
            services_ids.add(vuln['parent'])
        vulns_ids.add(vuln['_id'])

    comments = db.session.query(Comment)\
        .filter(Comment.object_type == 'vulnerability')\
        .filter(Comment.object_id.in_(vulns_ids)).all()
    for comment in comments:
        if comment.object_id in comments_dict:
            comments_dict[comment.object_id].append(comment.text)
        else:
            comments_dict[comment.object_id] = [comment.text]

    services_data = _build_services_data(services_ids)

    hosts_ids.update({elem['service_parent_id'] for elem in services_data.values()})

    hosts_data = _build_hosts_data(hosts_ids)

    for vuln in vulns:
        row = None
        vuln_data = _build_vuln_data(vuln, custom_fields_columns, comments_dict)
        if vuln['parent_type'] == 'Host':
            host_id = vuln['parent']
            host_data = hosts_data[host_id]
            row = {**vuln_data, **host_data}
        elif vuln['parent_type'] == 'Service':
            service_id = vuln['parent']
            service_data = services_data[service_id]
            host_id = service_data['service_parent_id']
            host_data = hosts_data[host_id]
            row = {**vuln_data, **host_data, **service_data}

        writer.writerow(row)

    memory_file = BytesIO()
    memory_file.write(buffer.getvalue().encode('utf8'))
    memory_file.seek(0)
    return memory_file


def _build_hosts_data(hosts_id):
    hosts = db.session.query(Host)\
                            .filter(Host.id.in_(hosts_id)).all()

    hosts_dict = {}

    for host in hosts:
        host_data = {
            "host_id": host.id,
            "host_description": host.description,
            "mac": host.mac,
            "host_owned": host.owned,
            "host_creator_id": host.creator_id,
            "host_date": host.create_date,
            "host_update_date": host.update_date,
        }

        hosts_dict[host.id] = host_data

    return hosts_dict


def _build_services_data(services_ids):
    services = db.session.query(Service)\
                            .filter(Service.id.in_(services_ids)).all()
    services_dict = {}

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
            "service_date": service.create_date,
            "service_update_date": service.update_date,
            "service_parent_id": service.host_id,
        }

        services_dict[service.id] = service_data

    return services_dict


def _build_vuln_data(vuln, custom_fields_columns, comments_dict):
    comments_list = comments_dict[vuln['_id']] if vuln['_id'] in comments_dict else []
    vuln_date = vuln['metadata']['create_time']
    if vuln['service']:
        service_fields = ["status", "protocol", "name", "summary", "version", "ports"]
        service_fields_values = [f"{field}:{vuln['service'][field]}" for field in service_fields]
        vuln_service = " - ".join(service_fields_values)
    else:
        vuln_service = ""

    if all(isinstance(hostname, str) for hostname in vuln['hostnames']):
        vuln_hostnames = vuln['hostnames']
    else:
        vuln_hostnames = [str(hostname['name']) for hostname in vuln['hostnames']]

    vuln_data = {
        "confirmed": vuln['confirmed'],
        "id": vuln.get('_id', None),
        "date": vuln_date,
        "name": vuln.get('name', None),
        "severity": vuln.get('severity', None),
        "service": vuln_service,
        "target": vuln.get('target', None),
        "desc": vuln.get('description', None),
        "status": vuln.get('status', None),
        "hostnames": vuln_hostnames,
        "comments": comments_list,
        "owner": vuln.get('owner', None),
        "os": vuln.get('host_os', None),
        "resolution": vuln.get('resolution', None),
        "refs": vuln.get('refs', None),
        "easeofresolution": vuln.get('easeofresolution', None),
        "web_vulnerability": vuln['type'] == "VulnerabilityWeb",
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
        "cve": vuln.get('cve', None),
        "cwe": vuln.get('cwe', None),
        "cvss2_vector_string": vuln.get('cvss2').get('vector_string', None),
        "cvss2_base_score": vuln.get('cvss2').get('base_score', None),
        "cvss3_vector_string": vuln.get('cvss3').get('vector_string', None),
        "cvss3_base_score": vuln.get('cvss3').get('base_score', None),
        "policyviolations": vuln.get('policyviolations', None),
        "external_id": vuln.get('external_id', None),
        "impact_confidentiality": vuln["impact"]["confidentiality"],
        "impact_integrity": vuln["impact"]["integrity"],
        "impact_availability": vuln["impact"]["availability"],
        "impact_accountability": vuln["impact"]["accountability"],
        "update_date": vuln['metadata'].get('update_time', None),
    }
    if vuln['custom_fields']:
        for field_name, value in vuln['custom_fields'].items():
            field_name = 'cf_' + field_name
            if field_name in custom_fields_columns:
                vuln_data.update({field_name: value})

    vuln_data = csv_escape(vuln_data)
    return vuln_data


# Patch possible formula injection attacks
def csv_escape(vuln_dict):
    for key, value in vuln_dict.items():
        if str(value).startswith('=') or str(value).startswith('+') or str(value).startswith('-') \
                or str(value).startswith('@'):
            # Convert value to str just in case is has another type (like a list or
            # dict). This would be done anyway by the csv writer.
            vuln_dict[key] = "'" + str(value)
    return vuln_dict
