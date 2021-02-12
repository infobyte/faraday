'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest
from lxml.etree import fromstring, tostring

from tests.conftest import TEST_DATA_PATH
from tests.factories import (
    WorkspaceFactory,
    HostFactory,
    ServiceFactory,
    VulnerabilityFactory,
    VulnerabilityWebFactory
)
from tests.utils.url import v2_to_v3


@pytest.mark.usefixtures('logged_user')
class TestExportData:

    def check_url(self, url):
        return url

    def test_export_data_without_format(self, test_client):
        workspace = WorkspaceFactory.create()
        url = self.check_url(f'/v2/ws/{workspace.name}/export_data')
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
            version='5.0',
            description='Description for service'
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
            description='Desc for testing web vuln',
            severity="high",
            path='faraday.com',
            method="GET",
            parameters="ABCDEF",
            parameter_name="qwerty",
            query_string="query for vuln",
            request="GET for vuln"
        )
        session.add(vuln_web)
        session.commit()

        url = self.check_url(f'/v2/ws/{workspace.name}/export_data?format=xml_metasploit')
        response = test_client.get(url)
        assert response.status_code == 200
        response_xml = response.data

        xml_file_path = TEST_DATA_PATH / \
                        'faraday_export_data_xml_metasploit.xml'
        with xml_file_path.open('rb') as output:
            xml_file = output.read()

        response_tree = fromstring(response_xml)
        xml_file_tree = fromstring(xml_file)

        xpaths_list = [
            {
                '//host': ['address', 'mac', 'name', 'comments']
            },
            {
                '//host/services/service': ['port', 'proto', 'state', 'name', 'info']
            },
            {
                '//MetasploitV4/services/service': ['port', 'proto', 'state', 'name', 'info']
            },
            {
                '//MetasploitV4/web_sites/web_site': ['vhost', 'host', 'port', 'comments', 'ssl']
            },
            {
                '//host/vulns/vuln': ['name', 'info']
            },
            {
                '//MetasploitV4/web_vulns/web_vuln': ['name', 'description', 'risk', 'path',
                                                        'method', 'params', 'pname', 'query',
                                                        'request', 'vhost', 'host', 'port', 'ssl']
            }
        ]

        for xpath_data in xpaths_list:
            for xpath, tags_list in xpath_data.items():
                for tag in tags_list:
                    full_xpath = xpath + '/' + tag
                    if full_xpath == '//host/name':
                        # Check hostnames list order
                        # Sometimes host.set_hostnames() switch the order of the hostnames list sent.
                        response_hostnames = response_tree.xpath(full_xpath)[0].text
                        xml_file_hostnames = xml_file_tree.xpath(full_xpath)[0].text
                        if response_hostnames != xml_file_hostnames:
                            # For testing purposes, response_hostnames list will be reordered.
                            response_hostnames = response_hostnames.split(',')
                            response_hostnames[0], response_hostnames[1] = response_hostnames[1], response_hostnames[0]
                            response_tree.xpath(full_xpath)[0].text = ','.join(response_hostnames)
                        assert response_tree.xpath(full_xpath)[0].text == xml_file_hostnames
                    else:
                        assert response_tree.xpath(full_xpath)[0].text == xml_file_tree.xpath(full_xpath)[0].text


class TestExportDataV3(TestExportData):

    def check_url(self, url):
        return v2_to_v3(url)
