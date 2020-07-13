import re
import csv
from io import StringIO, BytesIO
import logging

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
        "params", "pname", "query", "policyviolations", "external_id", "impact_confidentiality",
        "impact_integrity", "impact_availability", "impact_accountability", "update_date"
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

    hosts_data = {}
    services_data = {}
    for vuln in vulns:
        vuln_data = _build_vuln_data(vuln, custom_fields_columns)
        if vuln['parent_type'] == 'Host':
            host_id = vuln['parent']
            if host_id in hosts_data:
                host_data = hosts_data[host_id]
            else:
                host_data = _build_host_data(host_id)
                hosts_data[host_id] = host_data
            row = {**vuln_data, **host_data}
        elif vuln['parent_type'] == 'Service':
            service_id = vuln['parent']
            if service_id in services_data:
                service_data = services_data[service_id]
            else:
                service_data = _build_service_data(service_id)
                services_data[service_id] = service_data
            host_id = service_data['service_parent_id']
            if host_id in hosts_data:
                host_data = hosts_data[host_id]
            else:
                host_data = _build_host_data(host_id)
                hosts_data[host_id] = host_data
            row = {**vuln_data, **host_data, **service_data}

        writer.writerow(row)

    memory_file = BytesIO()
    memory_file.write(buffer.getvalue().encode('utf8'))
    memory_file.seek(0)
    return memory_file


def _build_host_data(host_id):
    host = db.session.query(Host)\
                            .filter(Host.id == host_id).one()

    host_data = {
        "host_id": host.id,
        "host_description": host.description,
        "mac": host.mac,
        "host_owned": host.owned,
        "host_creator_id": host.creator_id,
        "host_date": host.create_date,
        "host_update_date": host.update_date,
    }

    return host_data


def _build_service_data(service_id):
    service = db.session.query(Service)\
                            .filter(Service.id == service_id).one()
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

    return service_data


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

    vuln_data = {
        "confirmed": vuln['confirmed'],
        "id": vuln.get('_id', None),
        "date": vuln_date,
        "name": vuln.get('name', None),
        "severity": vuln.get('severity', None),
        "service": vuln_service,
        "target": vuln.get('target', None),
        "desc": vuln_description,
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
    for key,value in vuln_dict.items():
        if str(value).startswith('=') or str(value).startswith('+') or str(value).startswith('-') or str(value).startswith('@'):
            # Convert value to str just in case is has another type (like a list or
            # dict). This would be done anyway by the csv writer.
            vuln_dict[key] = "'" + str(value)
    return vuln_dict
