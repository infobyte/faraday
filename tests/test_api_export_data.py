'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import absolute_import

import os
import pytest
from lxml.etree import fromstring, tostring

from tests.factories import (
    WorkspaceFactory,
    HostFactory,
    ServiceFactory,
    VulnerabilityFactory,
    VulnerabilityWebFactory
)


@pytest.mark.usefixtures('logged_user')
class TestExportData():
    def test_export_data_without_format(self, test_client):
        workspace = WorkspaceFactory.create()
        url = '/v2/ws/{ws_name}/export_data'.format(ws_name=workspace.name)
        response = test_client.get(url)
        assert response.status_code == 400

    def test_export_data_xml_metasploit_format(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(
            workspace=workspace,
            ip='127.0.0.1',
            os='Linux',
            mac='30-65-EC-6F-C4-58',
            description='Host for test purposes'
        )
        host.set_hostnames(['localhost', 'test'])
        session.add(host)
        session.commit()

        # Hardcode create_date and update_date for tests purposes
        host.create_date = host.create_date.replace(2020, 4, 1, 20, 49, 31)
        host.update_date = host.update_date.replace(2020, 4, 1, 20, 49, 31)

        service = ServiceFactory.create(
            workspace=workspace,
            host=host,
            port=8080,
            protocol='tcp',
            status='open',
            name='Test service',
            version='5.0'
        )
        session.add(service)
        session.commit()

        # Hardcode create_date and update_date for tests purposes
        service.create_date = service.create_date.replace(2020, 4, 1, 20, 49, 49)
        service.update_date = service.update_date.replace(2020, 4, 1, 20, 49, 49)

        vuln = VulnerabilityFactory.create(
            workspace=workspace,
            host=host,
            service=None,
            name='Vulnerability test',
            description='Desc for testing'
        )
        session.add(vuln)

        vuln_web = VulnerabilityWebFactory.create(
            workspace=workspace,
            service=service,
            name='Vulnerability Web test',
            description='Desc for testing web vuln'
        )
        session.add(vuln_web)
        session.commit()

        url = '/v2/ws/{ws_name}/export_data?format=xml_metasploit'.format(ws_name=workspace.name)
        response = test_client.get(url)
        assert response.status_code == 200
        response_xml = response.data

        xml_file_path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                'data',
                'faraday_export_data_xml_metasploit.xml')
        with open(xml_file_path, 'rb') as output:
            xml_file = output.read()

        response_tree = fromstring(response_xml)
        xml_file_tree = fromstring(xml_file)
        # Check hostnames list order
        # Sometimes host.set_hostnames() switch the order of the hostnames list sent.
        response_hostnames = response_tree.xpath('//host/name')[0].text
        xml_file_hostnames = xml_file_tree.xpath('//host/name')[0].text
        if response_hostnames != xml_file_hostnames:
            # For testing purposes, response_hostnames list will be reordered.
            response_hostnames = response_hostnames.split(',')
            response_hostnames[0], response_hostnames[1] = response_hostnames[1], response_hostnames[0]
            response_tree.xpath('//host/name')[0].text = ','.join(response_hostnames)

        assert tostring(response_tree) == tostring(xml_file_tree)
