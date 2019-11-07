import csv
from io import StringIO, BytesIO
import re
import logging

from faraday.server.models import (
    db,
    Comment
)

logger = logging.getLogger(__name__)

def export_vulns_to_csv(vulns, custom_fields_columns=None):
    if custom_fields_columns is None:
        custom_fields_columns = []
    buffer = StringIO()
    headers = [
        "confirmed", "id", "date", "name", "severity", "service",
        "target", "desc", "status", "hostnames", "owner", "os", "resolution", "easeofresolution", "web_vulnerability",
        "data", "website", "path", "status_code", "request", "method", "params", "pname", "query",
        "policyviolations", "external_id", "impact_confidentiality", "impact_integrity", "impact_availability",
        "impact_accountability"
    ]
    headers += custom_fields_columns
    writer = csv.DictWriter(buffer, fieldnames=headers)
    writer.writeheader()
    for vuln in vulns:
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

        vuln_dict = {"confirmed": vuln['confirmed'],
                     "id": vuln['_id'],
                     "date": vuln_date,
                     "severity": vuln['severity'],
                     "target": vuln['target'],
                     "status": vuln['status'],
                     "hostnames": vuln_hostnames,
                     "desc": vuln_description,
                     "name": vuln['name'],
                     "service": vuln_service,
                     "owner": vuln['owner'],
                     "os": vuln['host_os'],
                     "resolution": vuln['resolution'],
                     "easeofresolution": vuln['easeofresolution'],
                     "data": vuln['data'],
                     "website": vuln['website'],
                     "path": vuln['path'],
                     "status_code": vuln['status_code'],
                     "request": vuln['request'],
                     "method": vuln['method'],
                     "params": vuln['params'],
                     "pname": vuln['pname'],
                     "query": vuln['query'],
                     "policyviolations": vuln['policyviolations'],
                     "external_id": vuln['external_id'],
                     "impact_confidentiality": vuln["impact"]["confidentiality"],
                     "impact_integrity": vuln["impact"]["integrity"],
                     "impact_availability": vuln["impact"]["availability"],
                     "impact_accountability": vuln["impact"]["accountability"],
                     "web_vulnerability": vuln['type'] == "VulnerabilityWeb"
        }
        if vuln['custom_fields']:
            for field_name, value in vuln['custom_fields'].items():
                if field_name in custom_fields_columns:
                    vuln_dict.update({field_name: value})
        writer.writerow(vuln_dict)
    memory_file = BytesIO()
    memory_file.write(buffer.getvalue().encode('utf-8'))
    memory_file.seek(0)
    return memory_file


