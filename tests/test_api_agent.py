"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from __future__ import absolute_import

from unittest import mock
import pytest

from faraday.server.api.modules.agent import AgentView
from faraday.server.models import Agent
from tests.factories import AgentFactory, WorkspaceFactory, ExecutorFactory
from tests.test_api_workspaced_base import ReadOnlyAPITests
from tests import factories


def http_req(method, client, endpoint, json_dict, expected_status_codes, follow_redirects=False):
    res = ""
    if method.upper() == "GET":
        res = client.get(endpoint, json=json_dict, follow_redirects=follow_redirects)
    elif method.upper() == "POST":
        res = client.post(endpoint, json=json_dict, follow_redirects=follow_redirects)
    elif method.upper() == "PUT":
        res = client.put(endpoint, json=json_dict, follow_redirects=follow_redirects)
    assert res.status_code in expected_status_codes
    return res


def logout(client, expected_status_codes):
    res = http_req(method="GET",
                   client=client,
                   endpoint="/logout",
                   json_dict=dict(),
                   expected_status_codes=expected_status_codes)
    return res


@pytest.mark.usefixtures('logged_user')
class TestAgentAuthTokenAPIGeneric():

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_token(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = None
        res = test_client.get('/v2/agent_token/')
        assert 'token' in res.json
        assert len(res.json['token'])

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_token_without_csrf_fails(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = None
        res = test_client.post('/v2/agent_token/')
        assert res.status_code == 403

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_new_agent_token(self, faraday_server_config, test_client, session, csrf_token):
        faraday_server_config.agent_token = None
        headers = {'Content-type': 'multipart/form-data'}
        res = test_client.post('/v2/agent_token/',
                               data={"csrf_token": csrf_token},
                               headers=headers,
                               use_json_data=False)
        assert res.status_code == 200
        assert len(res.json['token'])


class TestAgentCreationAPI():

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_valid_token(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = 'sarasa'
        workspace = WorkspaceFactory.create(name='test')
        session.add(workspace)
        session.commit()
        logout(test_client, [302])
        initial_agent_count = len(session.query(Agent).all())
        raw_data = {"token": 'sarasa', 'name': 'new_agent'}
        # /v2/ws/<workspace_name>/agent_registration/
        res = test_client.post('/v2/ws/{0}/agent_registration/'.format(workspace.name), data=raw_data)
        assert res.status_code == 201
        assert len(session.query(Agent).all()) == initial_agent_count + 1

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_without_name_fails(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = 'sarasa'
        workspace = WorkspaceFactory.create(name='test')
        session.add(workspace)
        session.commit()
        logout(test_client, [302])
        initial_agent_count = len(session.query(Agent).all())
        raw_data = {"token": 'sarasa'}
        # /v2/ws/<workspace_name>/agent_registration/
        res = test_client.post('/v2/ws/{0}/agent_registration/'.format(workspace.name), data=raw_data)
        assert res.status_code == 400
        assert len(session.query(Agent).all()) == initial_agent_count

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_invalid_token(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = 'sarasa'
        workspace = WorkspaceFactory.create(name='test')
        session.add(workspace)
        logout(test_client, [302])
        raw_data = {"token": 'INVALID', "name": "test agent"}
        # /v2/ws/<workspace_name>/agent_registration/
        res = test_client.post('/v2/ws/{0}/agent_registration/'.format(workspace.name), data=raw_data)
        assert res.status_code == 401

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_agent_token_not_set(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = None
        workspace = WorkspaceFactory.create(name='test')
        session.add(workspace)
        logout(test_client, [302])
        raw_data = {"name": "test agent"}
        # /v2/ws/<workspace_name>/agent_registration/
        res = test_client.post('/v2/ws/{0}/agent_registration/'.format(workspace.name), data=raw_data)
        assert res.status_code == 400

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_invalid_payload(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = None
        workspace = WorkspaceFactory.create(name='test')
        session.add(workspace)
        logout(test_client, [302])
        raw_data = {"PEPE": 'INVALID'}
        # /v2/ws/<workspace_name>/agent_registration/
        res = test_client.post('/v2/ws/{0}/agent_registration/'.format(workspace.name), data=raw_data)
        assert res.status_code == 400


class TestAgentAPIGeneric(ReadOnlyAPITests):
    model = Agent
    factory = factories.AgentFactory
    view_class = AgentView
    api_endpoint = 'agents'

    def create_raw_agent(self, _type='shared', active=False, token="TOKEN"):
        return {
            "token": token,
            "active": active,
            "name": "My agent"
        }

    def test_create_agent_invalid(self, test_client, session):
        """
            To create new agent use the
            <Rule '/v2/ws/<workspace_name>/agent_registration/' (POST, OPTIONS)
        """
        initial_agent_count = len(session.query(Agent).all())
        raw_agent = self.create_raw_agent()
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 405  # the only way to create agents is by using the token!
        assert len(session.query(Agent).all()) == initial_agent_count

    def test_update_agent(self, test_client, session):
        agent = AgentFactory.create(workspace=self.workspace, active=True)
        session.commit()
        raw_agent = self.create_raw_agent(active=False)
        res = test_client.put(self.url(agent.id), data=raw_agent)
        assert res.status_code == 200
        assert not res.json['active']

    def test_update_bug_case(self, test_client, session):
        agent = AgentFactory.create(workspace=self.workspace)
        session.add(agent)
        session.commit()
        update_data = {"id": 1, "name": "Agent test", "is_online": True}
        res = test_client.put(self.url(agent.id), data=update_data)
        assert res.status_code == 200

    def test_delete_agent(self, test_client, session):
        initial_agent_count = len(session.query(Agent).all())
        agent = AgentFactory.create(workspace=self.workspace)
        session.commit()
        assert len(session.query(Agent).all()) == initial_agent_count + 1
        res = test_client.delete(self.url(agent.id))
        assert res.status_code == 204
        assert len(session.query(Agent).all()) == initial_agent_count

    def test_run_agent_invalid_missing_executorData(self, csrf_token, session, test_client):
        agent = AgentFactory.create(workspace=self.workspace)
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token
        }
        res = test_client.post(self.url() + f'{agent.id}/run/', json=payload)
        assert res.status_code == 400

    def test_invalid_body(self, test_client, session):
        agent = AgentFactory.create(workspace=self.workspace)
        session.add(agent)
        session.commit()
        res = test_client.post(self.url() + f'{agent.id}/run/', data='[" broken]"{')
        assert res.status_code == 400

    def test_invalid_content_type(self, test_client, session, csrf_token):
        agent = AgentFactory.create(workspace=self.workspace)
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': {
                "args": {
                    "param1": True
                },
                "executor": "executor_name"
            },
        }
        headers = [
            ('content-type', 'text/html'),
        ]
        res = test_client.post(
            self.url() + f'{agent.id}/run/',
            data=payload,
            headers=headers)
        assert res.status_code == 400

    def test_invalid_executor(self, test_client, session, csrf_token):
        agent = AgentFactory.create(workspace=self.workspace)
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': {
                "args": {
                    "param1": True
                },
                "executor": "executor_name"
            },
        }
        res = test_client.post(self.url() + f'{agent.id}/run/',json=payload)
        assert res.status_code == 400

    def test_happy_path_valid_json(self, test_client, session, csrf_token):
        agent = AgentFactory.create(workspace=self.workspace)
        executor = ExecutorFactory.create(agent=agent)

        session.add(executor)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': {
                "args": {
                    "param1": True
                },
                "executor": executor.name
            },
        }
        res = test_client.post(self.url() + f'{agent.id}/run/', json=payload)
        assert res.status_code == 200

    def test_invalid_json_on_executorData_breaks_the_api(self, csrf_token, session, test_client):
        agent = AgentFactory.create(workspace=self.workspace)
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': '[][dassa',
        }
        res = test_client.post(self.url() + f'{agent.id}/run/', json=payload)
        assert res.status_code == 400

    def test_run_agent(self, session, csrf_token, test_client):
        agent = AgentFactory.create(workspace=self.workspace)
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': '',
        }
        res = test_client.post(self.url() + f'{agent.id}/run/', json=payload)
        assert res.status_code == 400
