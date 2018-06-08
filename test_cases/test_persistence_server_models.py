'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import persistence.server.models as models
import pytest
import responses
import requests
from mock import Mock, patch

import server.config

from test_api_workspaced_base import GenericAPITest

from test_cases.factories import VulnerabilityWebFactory, VulnerabilityFactory


@pytest.mark.usefixtures('logged_user')
class TestVulnPersistanceModelsFuncions(GenericAPITest):
    factory = VulnerabilityFactory

    @responses.activate
    @patch('config.configuration.getInstanceConfiguration')
    @patch('persistence.server.server.SERVER_URL', 'http://localhost:5985')
    def test_persistence_server_update_vuln(self, getInstanceConfigurationMock):
        fo = self.first_object
        conf_mock = Mock()
        getInstanceConfigurationMock.return_value = conf_mock
        port = 5985
        conf_mock.getDBSessionCookies.return_value = None
        conf_mock.getAPIUrl.return_value = 'http://localhost:{0}'.format(port)
        conf_mock.getServerURI.return_value = 'http://localhost:{0}'.format(port)
        conf_mock.getAPIUsername.return_value = 'faraday'
        conf_mock.getAPIPassword.return_value = 'mocked_password'

        vuln = {'desc': fo.description, 'data': fo.data, 'severity': fo.severity, 'refs': list(fo.references),
                'confirmed': fo.confirmed, 'resolution': fo.resolution, 'status': fo.status,
                'policyviolations': list(fo.policy_violations)}

        v = models.Vuln(vuln, self.workspace.name)
        v.id = fo.id

        resp = {u'status': u'closed',
                u'_rev': u'',
                u'parent_type': v.getParentType(),
                u'owned': v.isOwned(),
                u'owner': v.getParent(),
                u'query': u'',
                u'refs': v.getRefs(),
                u'impact': {u'integrity': False, u'confidentiality': False, u'availability': False,
                            u'accountability': False},
                u'confirmed': v.getConfirmed(),
                u'severity': v.getSeverity(),
                u'service': None,
                u'policyviolations': v.getPolicyViolations(),
                u'params': u'',
                u'type': u'Vulnerability',
                u'method': u'',
                u'metadata': {u'update_time': u'2018-05-23T17:03:27.880196+00:00', u'update_user': u'<User: faraday>',
                              u'update_action': 0, u'creator': u'Nmap',
                              u'create_time': u'2018-05-18T16:30:26.011851+00:00',
                              u'update_controller_action': u'', u'owner': u'faraday', u'command_id': 22},
                u'website': u'',
                u'issuetracker': {},
                u'description': v.getDesc(),
                u'tags': [],
                u'easeofresolution': None,
                u'hostnames': [],
                u'pname': u'',
                u'date': u'2018-05-18T16:30:26.011851+00:00',
                u'path': u'',
                u'data': v.getData(),
                u'response': u'',
                u'desc': v.getDesc(),
                u'name': v.getName(),
                u'obj_id': str(v.getID()),
                u'request': u'',
                u'_attachments': {},
                u'target': u'192.168.10.103',
                u'_id': v.getID(),
                u'resolution': v.getResolution()
                }

        responses.add(responses.PUT,
                      'http://localhost:{0}/_api/v2/ws/{1}/vulns/{2}/'.format(port,self.workspace.name, v.id),
                      json=resp, status=200)

        a = requests.put('http://localhost:{0}/_api/v2/ws/{1}/vulns/{2}/'.format(port,self.workspace.name, v.id))

        models.update_vuln(self.workspace.name, v)


@pytest.mark.usefixtures('logged_user')
class TestVulnWebPersistanceModelsFuncions(GenericAPITest):
    factory = VulnerabilityWebFactory

    @responses.activate
    @patch('config.configuration.getInstanceConfiguration')
    @patch('persistence.server.server.SERVER_URL', 'http://localhost:5985')
    def test_persistence_server_update_vuln_web(self, getInstanceConfigurationMock):
        fo = self.first_object

        conf_mock = Mock()
        getInstanceConfigurationMock.return_value = conf_mock
        port = 5985
        conf_mock.getDBSessionCookies.return_value = None
        conf_mock.getAPIUrl.return_value = 'http://localhost:{0}'.format(port)
        conf_mock.getServerURI.return_value = 'http://localhost:{0}'.format(port)
        conf_mock.getAPIUsername.return_value = 'faraday'
        conf_mock.getAPIPassword.return_value = 'mocked_password'

        vuln_web = {'desc': fo.description, 'data': fo.data, 'severity': fo.severity, 'refs': list(fo.references),
                    'confirmed': fo.confirmed, 'resolution': fo.resolution, 'status': fo.status,
                    'policyviolations': list(fo.policy_violations), 'path': fo.path, 'website': fo.website,
                    'request': fo.request, 'response': fo.response, 'method': fo.method, 'params': fo.parameters,
                    'pname': fo.parameter_name, 'query': str(fo.query), '_attachments': fo.attachments,
                    'hostnames': list(fo.hostnames),
                    'impact': {'accountability': fo.impact_accountability, 'availability': fo.impact_availability,
                               'confidentiality': fo.impact_confidentiality, 'integrity': fo.impact_integrity},
                    'service': fo.service_id, 'tags': list(fo.tags), 'target': fo.target_host_ip}

        v = models.VulnWeb(vuln_web, self.workspace.name)
        v.id = fo.id

        resp = {u'status': u'closed',
                u'_rev': u'',
                u'parent_type': v.getParentType(),
                u'owned': v.isOwned(),
                u'owner': v.getParent(),
                u'query': str(v.getQuery()),
                u'refs': v.getRefs(),
                u'impact': v.getImpact(),
                u'confirmed': v.getConfirmed(),
                u'severity': v.getSeverity(),
                u'service': v.getService(),
                u'policyviolations': v.getPolicyViolations(),
                u'params': v.getParams(),
                u'type': u'VulnerabilityWeb',
                u'method': v.getMethod(),
                u'metadata': {u'update_time': u'2018-05-23T17:03:27.880196+00:00', u'update_user': u'<User: faraday>',
                              u'update_action': 0, u'creator': u'Nmap',
                              u'create_time': u'2018-05-18T16:30:26.011851+00:00',
                              u'update_controller_action': u'', u'owner': u'faraday', u'command_id': 22},
                u'website': v.getWebsite(),
                u'issuetracker': {},
                u'description': v.getDesc(),
                u'tags': v.getTags(),
                u'easeofresolution': None,
                u'hostnames': v.getHostnames(),
                u'pname': v.getPname(),
                u'date': u'2018-05-18T16:30:26.011851+00:00',
                u'path': v.getPath(),
                u'data': v.getData(),
                u'response': v.getResponse(),
                u'desc': v.getDesc(),
                u'name': v.getName(),
                u'obj_id': str(v.getID()),
                u'request': v.getRequest(),
                u'_attachments': str(v.getAttachments()),
                u'target': v.getTarget(),
                u'_id': v.getID(),
                u'resolution': v.getResolution()
                }

        responses.add(responses.PUT,
                      'http://localhost:{0}/_api/v2/ws/{1}/vulns/{2}/'.format(port,self.workspace.name, v.id),
                      json=resp, status=200)

        a = requests.put('http://localhost:{0}/_api/v2/ws/{1}/vulns/{2}/'.format(port,self.workspace.name, v.id))

        models.update_vuln_web(self.workspace.name, v)
