
import logging
from io import BytesIO
from lxml.etree import Element, SubElement, tostring
from flask import Blueprint, request, abort, send_file

from faraday.server.models import Workspace

export_data_api = Blueprint('export_data_api', __name__)

logger = logging.getLogger(__name__)


@export_data_api.route('/v2/ws/<workspace_name>/export_data', methods=['GET'])
def export_data(workspace_name):
    workspace = Workspace.query.filter_by(name=workspace_name).one()
    export_format = request.args.get('format', '')
    if not export_format:
        logger.error("No format specified. Please, specify the format to export the data.")
        abort(400, "No format specified.")

    if export_format == 'xml_metasploit':
        memory_file = xml_metasploit_format(workspace)
        return send_file(
            memory_file,
            attachment_filename="Faraday-%s-data.xml" % workspace_name,
            as_attachment=True,
            cache_timeout=-1
        )
    else:
        logger.error("Invalid format. Please, specify a valid format.")
        abort(400, "Invalid format.")


def _build_websites_element(web_services, websites_tag):
    web_site_tag = SubElement(websites_tag, 'web_site')
    for web_service in web_services:
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
        create_date.text = web_site_tag.create_date.strftime("%Y-%m-%d %H:%M:%S")
        update_date = SubElement(web_site_tag, 'updated-at')
        update_date.text = web_site_tag.update_date.strftime("%Y-%m-%d %H:%M:%S")

        website_comments = SubElement(web_site_tag, 'comments')
        website_comments.text = str(web_service.description)

        website_options = SubElement(web_site_tag, 'options')
        website_options.text = ''

        website_ssl = SubElement(web_site_tag, 'ssl')
        website_ssl.text = 'true' if web_service.port == 443 else ''


def xml_metasploit_format(workspace):
    root = Element('MetasploitV4')
    hosts_tag = SubElement(root, 'hosts')
    services_tag = SubElement(root, 'services')  # Element's parent is root
    websites_tag = SubElement(root, 'web_sites')
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
                vuln_tag = SubElement(vulns_tag, 'vuln')
                web_services.add(vuln_web.service)
                _build_vuln_web_element(vuln_web, vuln_tag)


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
    vuln_count.text = str(host.vulnerability_count)
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


def _build_vuln_web_element(vuln, vuln_tag):
    vuln_id = SubElement(vuln_tag, 'id')
    vuln_id.text = str(vuln.id)

    website_id = SubElement(vuln_tag, 'web-site-id')
    website_id.text = str(vuln.service_id)

    vuln_name = SubElement(vuln_tag, 'name')
    vuln_name.text = vuln.name
    vuln_info = SubElement(vuln_tag, 'info')
    vuln_info.text = vuln.description

    #update_date = SubElement(vuln_tag, 'updated-at')
    #update_date.text = service.update_date.strftime("%Y-%m-%d %H:%M:%S")
    #create_date = SubElement(vuln_tag, 'updated-at')
    #create_date.text = service.update_date.strftime("%Y-%m-%d %H:%M:%S")
    # ADD all vuln fields