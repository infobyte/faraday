# Standard library imports
import logging
from io import BytesIO

# Related third party imports
from lxml.etree import (  # nosec
    Element,  # We don't use Element for parsing
    SubElement,
    tostring,
)
from flask import Blueprint, request, abort, send_file
from marshmallow import Schema

# Local application imports
from faraday.server.api.base import GenericWorkspacedView
from faraday.server.models import Workspace

export_data_api = Blueprint('export_data_api', __name__)
logger = logging.getLogger(__name__)


class EmptySchema(Schema):
    pass


class ExportDataView(GenericWorkspacedView):
    route_base = 'export_data'
    schema_class = EmptySchema

    def get(self, workspace_name):
        """
        ---
        get:
          tags: ["File","Workspace"]
          description: Exports all the workspace data in a XML file
          responses:
            200:
              description: Ok
        """

        workspace = Workspace.query.filter_by(name=workspace_name).first()
        if not workspace:
            logger.error("No such workspace. Please, specify a valid workspace.")
            abort(404, f"No such workspace: {workspace_name}")

        export_format = request.args.get('format', '')
        if not export_format:
            logger.error("No format specified. Please, specify the format to export the data.")
            abort(400, "No format specified.")

        if export_format == 'xml_metasploit':
            memory_file = xml_metasploit_format(workspace)
            logger.info("Workspace´s data exported")
            return send_file(
                memory_file,
                attachment_filename=f"Faraday-{workspace_name}-data.xml",
                as_attachment=True,
                cache_timeout=-1
            )
        else:
            logger.error("Invalid format. Please, specify a valid format.")
            abort(400, "Invalid format.")


ExportDataView.register(export_data_api)


def xml_metasploit_format(workspace):
    root = Element('MetasploitV4')
    hosts_tag = SubElement(root, 'hosts')
    services_tag = SubElement(root, 'services')  # Element's parent is root
    websites_tag = SubElement(root, 'web_sites')
    web_vulns_tag = SubElement(root, 'web_vulns')
    web_services = set()
    for host in workspace.hosts:
        host_tag = SubElement(hosts_tag, 'host')
        _build_host_element(host, host_tag)

        host_services_tag = SubElement(host_tag, 'services')  # Element's parent is host
        vulns_tag = SubElement(host_tag, 'vulns')
        for service in host.services:
            host_service_tag = SubElement(host_services_tag, 'service')
            _build_service_element(service, host_service_tag)

            service_tag = SubElement(services_tag, 'service')
            _build_service_element(service, service_tag)
            for vuln in service.vulnerabilities:
                vuln_tag = SubElement(vulns_tag, 'vuln')
                _build_vuln_element(vuln, vuln_tag)

            for vuln_web in service.vulnerabilities_web:
                web_services.add(vuln_web.service)
                web_vuln_tag = SubElement(web_vulns_tag, 'web_vuln')
                _build_vuln_web_element(vuln_web, web_vuln_tag)

        for vuln in host.vulnerabilities:
            vuln_tag = SubElement(vulns_tag, 'vuln')
            _build_vuln_element(vuln, vuln_tag)

    _build_websites_element(web_services, websites_tag)

    memory_file = BytesIO()
    memory_file.write(tostring(root, xml_declaration=True, encoding="utf-8", pretty_print=True))
    memory_file.seek(0)
    return memory_file


def _build_host_element(host, host_tag):
    host_id = SubElement(host_tag, 'id')
    host_id.text = str(host.id)
    create_date = SubElement(host_tag, 'created-at')
    create_date.text = host.create_date.strftime("%Y-%m-%d %H:%M:%S")
    address = SubElement(host_tag, 'address')
    address.text = host.ip
    mac_address = SubElement(host_tag, 'mac')
    mac_address.text = host.mac
    name = SubElement(host_tag, 'name')
    name.text = ','.join([hostname.name for hostname in host.hostnames])
    os = SubElement(host_tag, 'os-name')
    os.text = host.os
    update_date = SubElement(host_tag, 'updated-at')
    update_date.text = host.update_date.strftime("%Y-%m-%d %H:%M:%S")
    host_description = SubElement(host_tag, 'comments')
    host_description.text = host.description
    vuln_count = SubElement(host_tag, 'vuln-count')
    vuln_count.text = str(len(host.vulnerabilities))
    service_count = SubElement(host_tag, 'service-count')
    service_count.text = str(len(host.services))
    _build_host_empty_fields(host_tag)


def _build_host_empty_fields(host_tag):
    empty_fields = ["comm", "state", "os-flavor", "os-sp", "os-lang", "purpose"]
    for field in empty_fields:
        SubElement(host_tag, field)


def _build_service_element(service, service_tag):
    service_id = SubElement(service_tag, 'id')
    service_id.text = str(service.id)
    create_date = SubElement(service_tag, 'created-at')
    create_date.text = service.create_date.strftime("%Y-%m-%d %H:%M:%S")
    host_id = SubElement(service_tag, 'host-id')
    host_id.text = str(service.host_id)
    port = SubElement(service_tag, 'port')
    port.text = str(service.port)
    protocol = SubElement(service_tag, 'proto')
    protocol.text = service.protocol
    status = SubElement(service_tag, 'state')
    status.text = service.status
    service_name = SubElement(service_tag, 'name')
    service_name.text = service.name
    update_date = SubElement(service_tag, 'updated-at')
    update_date.text = service.update_date.strftime("%Y-%m-%d %H:%M:%S")
    service_version = SubElement(service_tag, 'info')
    service_version.text = service.version


def _build_vuln_element(vuln, vuln_tag):
    vuln_id = SubElement(vuln_tag, 'id')
    vuln_id.text = str(vuln.id)
    if vuln.service:
        host_id = SubElement(vuln_tag, 'host-id')
        host_id.text = str(vuln.service.host_id)
        service_id = SubElement(vuln_tag, 'service-id')
        service_id.text = str(vuln.service_id)
        website_id = SubElement(vuln_tag, 'web-site-id')
        website_id.text = str(vuln.service_id)
    else:
        host_id = SubElement(vuln_tag, 'host-id')
        host_id.text = str(vuln.host_id)
    vuln_name = SubElement(vuln_tag, 'name')
    vuln_name.text = vuln.name
    vuln_info = SubElement(vuln_tag, 'info')
    vuln_info.text = vuln.description
    vuln_refs_tag = SubElement(vuln_tag, 'refs')
    for ref in vuln.refs:
        vuln_ref = SubElement(vuln_refs_tag, 'ref')
        vuln_ref.text = ref.name


def _build_vuln_web_element(vuln, vuln_tag):
    vuln_id = SubElement(vuln_tag, 'id')
    vuln_id.text = str(vuln.id)

    website_id = SubElement(vuln_tag, 'web-site-id')
    website_id.text = str(vuln.service_id)

    create_date = SubElement(vuln_tag, 'created-at')
    create_date.text = vuln.update_date.strftime("%Y-%m-%d %H:%M:%S")
    update_date = SubElement(vuln_tag, 'updated-at')
    update_date.text = vuln.update_date.strftime("%Y-%m-%d %H:%M:%S")

    vuln_name = SubElement(vuln_tag, 'name')
    vuln_name.text = vuln.name
    vuln_desc = SubElement(vuln_tag, 'description')
    vuln_desc.text = vuln.description
    risk = SubElement(vuln_tag, 'risk')
    risk.text = map_severity(vuln.severity)
    legacy_category = SubElement(vuln_tag, 'legacy-category')
    legacy_category.text = "Faraday"

    path = SubElement(vuln_tag, 'path')
    path.text = vuln.path or "/"
    method = SubElement(vuln_tag, 'method')
    method.text = vuln.method or "GET"
    params = SubElement(vuln_tag, 'params')
    params.text = ''
    pname = SubElement(vuln_tag, 'pname')
    pname.text = vuln.parameter_name
    query = SubElement(vuln_tag, 'query')
    query.text = vuln.query_string
    _request = SubElement(vuln_tag, 'request')
    _request.text = vuln.request

    vhost = SubElement(vuln_tag, 'vhost')
    vhost.text = str(vuln.service.host.ip)
    host = SubElement(vuln_tag, 'host')
    host.text = str(vuln.service.host.ip)
    port = SubElement(vuln_tag, 'port')
    port.text = str(vuln.service.port)
    ssl = SubElement(vuln_tag, 'ssl')
    ssl.text = 'true' if vuln.service.port == 443 else ''

    confidence = SubElement(vuln_tag, 'confidence')
    confidence.text = ''


def map_severity(severity):
    risk = '1'
    if severity in ['high', 'critical']:
        risk = '5'
    elif severity == 'medium':
        risk = '4'
    elif severity == 'low':
        risk = '3'
    elif severity == 'informational':
        risk = '2'

    return risk


def _build_websites_element(web_services, websites_tag):
    for web_service in web_services:
        web_site_tag = SubElement(websites_tag, 'web_site')
        website_id = SubElement(web_site_tag, 'id')
        website_id.text = str(web_service.id)
        website_service_id = SubElement(web_site_tag, 'service-id')
        website_service_id.text = str(web_service.id)

        website_vhost = SubElement(web_site_tag, 'vhost')
        website_vhost.text = str(web_service.host.ip)
        website_host = SubElement(web_site_tag, 'host')
        website_host.text = str(web_service.host.ip)
        website_port = SubElement(web_site_tag, 'port')
        website_port.text = str(web_service.port)

        create_date = SubElement(web_site_tag, 'created-at')
        create_date.text = web_service.create_date.strftime("%Y-%m-%d %H:%M:%S")
        update_date = SubElement(web_site_tag, 'updated-at')
        update_date.text = web_service.update_date.strftime("%Y-%m-%d %H:%M:%S")

        website_comments = SubElement(web_site_tag, 'comments')
        website_comments.text = str(web_service.description)

        website_options = SubElement(web_site_tag, 'options')
        website_options.text = ''

        website_ssl = SubElement(web_site_tag, 'ssl')
        website_ssl.text = 'true' if web_service.port == 443 else ''
