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

        xpaths = [
            '//host/address',
            '//host/mac',
            '//host/name',
            '//host/comments',
            '//host/services/service/port',
            '//host/services/service/proto',
            '//host/services/service/state',
            '//host/services/service/name',
            '//host/services/service/info',
            '//MetasploitV4/services/service/port',
            '//MetasploitV4/services/service/proto',
            '//MetasploitV4/services/service/state',
            '//MetasploitV4/services/service/name',
            '//MetasploitV4/services/service/info',
            '//host/vulns/vuln',
        ]

        for xpath in xpaths:
            if xpath == '//host/vulns/vuln':
                response_vulns = response_tree.xpath(xpath)
                xml_file_vulns = xml_file_tree.xpath(xpath)
                response_vuln1_name = response_vulns[0].xpath('./name')[0].text
                response_vuln1_desc = response_vulns[0].xpath('./info')[0].text
                response_vuln2_name = response_vulns[1].xpath('./name')[0].text
                response_vuln2_desc = response_vulns[1].xpath('./info')[0].text

                xml_file_vuln1_name = xml_file_vulns[0].xpath('./name')[0].text
                xml_file_vuln1_desc = xml_file_vulns[0].xpath('./info')[0].text
                xml_file_vuln2_name = xml_file_vulns[1].xpath('./name')[0].text
                xml_file_vuln2_desc = xml_file_vulns[1].xpath('./info')[0].text

                assert response_vuln1_name == xml_file_vuln1_name
                assert response_vuln2_name == xml_file_vuln2_name
                assert response_vuln1_desc == xml_file_vuln1_desc
                assert response_vuln2_desc == xml_file_vuln2_desc
            elif xpath == '//host/name':
                # Check hostnames list order
                # Sometimes host.set_hostnames() switch the order of the hostnames list sent.
                response_hostnames = response_tree.xpath('//host/name')[0].text
                xml_file_hostnames = xml_file_tree.xpath('//host/name')[0].text
                if response_hostnames != xml_file_hostnames:
                    # For testing purposes, response_hostnames list will be reordered.
                    response_hostnames = response_hostnames.split(',')
                    response_hostnames[0], response_hostnames[1] = response_hostnames[1], response_hostnames[0]
                    response_tree.xpath('//host/name')[0].text = ','.join(response_hostnames)
                assert response_tree.xpath('//host/name')[0].text == xml_file_hostnames
            else:
                assert response_tree.xpath(xpath)[0].text == xml_file_tree.xpath(xpath)[0].text
