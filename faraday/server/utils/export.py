import csv
from StringIO import StringIO
from io import BytesIO
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
        "target", "desc", "status", "hostnames", "comments", "owner", "os", "resolution", "easeofresolution", "web_vulnerability",
        "data", "website", "path", "status_code", "request", "method", "params", "pname", "query",
        "policyviolations", "external_id", "impact_confidentiality", "impact_integrity", "impact_availability",
        "impact_accountability"
    ]
    headers += custom_fields_columns
    writer = csv.DictWriter(buffer, fieldnames=headers)
    writer.writeheader()
    for vuln in vulns:
        comments = []
        for comment in db.session.query(Comment).filter_by(object_type='vulnerability', object_id=vuln['_id']).all():
            comments.append(comment.text)
        vuln_description = re.sub(' +', ' ', vuln['description'].strip().replace("\n", ""))
        vuln_date = vuln['metadata']['create_time']
        if vuln['service']:
            service_fields = ["status", "protocol", "name", "summary", "version", "ports"]
            service_fields_values = ["%s:%s" % (field, vuln['service'][field]) for field in service_fields]
            vuln_service = " - ".join(service_fields_values)
        else:
            vuln_service = ""
        if all(isinstance(hostname, (str, unicode)) for hostname in vuln['hostnames']):
            vuln_hostnames = vuln['hostnames']
        else:
            vuln_hostnames = [str(hostname['name']) for hostname in vuln['hostnames']]

        vuln_dict = {"confirmed": vuln['confirmed'],
                     "id": vuln.get('_id', None),
                     "date": vuln_date,
                     "severity": vuln.get('severity', None),
                     "target": vuln.get('target', None),
                     "status": vuln.get('status', None),
                     "hostnames": vuln_hostnames,
                     "desc": vuln_description,
                     "name": vuln.get('name', None),
                     "service": vuln_service,
                     "comments": comments,
                     "owner": vuln.get('owner', None),
                     "os": vuln.get('host_os', None),
                     "resolution": vuln.get('resolution', None),
                     "easeofresolution": vuln.get('easeofresolution', None),
                     "data": vuln.get('data', None),
                     "website": vuln.get('website', None),
                     "path": vuln.get('path', None),
                     "status_code": vuln.get('status_code', None),
                     "request": vuln.get('request', None),
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
                     "web_vulnerability": vuln['type'] == "VulnerabilityWeb"
        }
        if vuln['custom_fields']:
            for field_name, value in vuln['custom_fields'].items():
                if field_name in custom_fields_columns:
                    vuln_dict.update({field_name: value})
        res = {}
        for key, value in vuln_dict.items():
            if isinstance(value, (str, unicode)):
                res[key] = value.encode('utf8')
            else:
                res[key] = value
        writer.writerow(res)
    memory_file = BytesIO()
    memory_file.write(buffer.getvalue())
    memory_file.seek(0)
    return memory_file


