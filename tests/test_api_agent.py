"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from unittest import mock

from posixpath import join
from urllib.parse import urljoin
from html import unescape
import pyotp
import pytest

from faraday.server.api.modules.agent import AgentView
from faraday.server.models import Agent, Command
from tests.factories import AgentFactory, WorkspaceFactory, ExecutorFactory
from tests.test_api_non_workspaced_base import ReadWriteAPITests
from tests import factories
from tests.test_api_workspaced_base import API_PREFIX


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


def get_raw_agent(name="My agent", active=None, token=None):
    raw_agent = {}
    if name is not None:
        raw_agent["name"] = name
    if active is not None:
        raw_agent["active"] = active
    if token:
        raw_agent["token"] = token
    return raw_agent


@pytest.mark.usefixtures('logged_user')
class TestAgentAuthTokenAPIGeneric:

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_get_agent_token(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_registration_secret = None
        res = test_client.get('/v3/agent_token')
        assert 'token' in res.json and 'expires_in' in res.json
        assert len(res.json['token'])

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_token_fails(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_registration_secret = None
        res = test_client.post('/v3/agent_token')
        assert res.status_code == 405


class TestAgentCreationAPI:

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_create_agent_valid_token(self, faraday_server_config, test_client,
                                      session):
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        faraday_server_config.agent_token_expiration = 60
        logout(test_client, [302])
        initial_agent_count = len(session.query(Agent).all())
        raw_data = get_raw_agent(
            name='new_agent',
            token=pyotp.TOTP(secret, interval=60).now()
        )
        res = test_client.post('/v3/agents', data=raw_data)
        assert res.status_code == 201, (res.json, raw_data)
        assert len(session.query(Agent).all()) == initial_agent_count + 1

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_without_name_fails(self, faraday_server_config,
                                             test_client, session):
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        faraday_server_config.agent_token_expiration = 60
        logout(test_client, [302])
        initial_agent_count = len(session.query(Agent).all())
        raw_data = get_raw_agent(
            name=None,
            token=pyotp.TOTP(secret, interval=60).now(),
        )
        res = test_client.post(
            '/v3/agents',
            data=raw_data
        )
        assert res.status_code == 400
        assert len(session.query(Agent).all()) == initial_agent_count

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_invalid_token(self, faraday_server_config,
                                        test_client, session):
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        logout(test_client, [302])
        raw_data = get_raw_agent(
            token="INVALID",
            name="test agent",
        )
        res = test_client.post('/v3/agents', data=raw_data)
        assert res.status_code == 401

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_agent_token_not_set(self, faraday_server_config,
                                              test_client, session):
        faraday_server_config.agent_registration_secret = None
        logout(test_client, [302])
        raw_data = get_raw_agent(
            name="test agent",
        )
        res = test_client.post('/v3/agents', data=raw_data)
        assert res.status_code == 400

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_invalid_payload(self, faraday_server_config,
                                          test_client, session):
        faraday_server_config.agent_registration_secret = None
        logout(test_client, [302])
        raw_data = {"PEPE": 'INVALID'}
        res = test_client.post('/v3/agents', data=raw_data)
        assert res.status_code == 400


class TestAgentAPIGeneric(ReadWriteAPITests):
    model = Agent
    factory = factories.AgentFactory
    view_class = AgentView
    api_endpoint = 'agents'
    patchable_fields = ['name']

    def test_create_succeeds(self, test_client):
        with pytest.raises(AssertionError) as exc_info:
            super().test_create_succeeds(test_client)
        assert '401' in exc_info.value.args[0]

    def workspaced_url(self, workspace, obj=None):
        url = urljoin(API_PREFIX, f"{workspace.name}{self.api_endpoint}")
        if obj is not None:
            id_ = str(obj.id) if isinstance(obj, self.model) else str(obj)
            url = urljoin(url, id_)
        return url

    def create_raw_agent(self, active=False, token="TOKEN"):
        return get_raw_agent(name="My agent", token=token, active=active)

    def test_update_agent(self, test_client, session):
        agent = AgentFactory.create(active=True)
        session.commit()
        raw_agent = self.create_raw_agent(active=False)
        res = test_client.put(self.url(agent.id), data=raw_agent)
        assert res.status_code == 200, (res.json, raw_agent)
        assert not res.json['active']

    def test_update_bug_case(self, test_client, session):
        agent = AgentFactory.create()
        session.add(agent)
        session.commit()
        update_data = {
            "id": 1,
            "name": "Agent test",
            "sid": "super_sid",
        }
        res = test_client.put(self.url(agent.id), data=update_data)
        assert res.status_code == 200, (res.json, update_data)

    def test_delete_agent(self, test_client, session):
        initial_agent_count = len(session.query(Agent).all())
        agent = AgentFactory.create()
        session.commit()
        assert len(session.query(Agent).all()) == initial_agent_count + 1
        res = test_client.delete(self.url(agent.id))
        assert res.status_code == 204
        assert len(session.query(Agent).all()) == initial_agent_count

    def test_run_fails(self, test_client, session, csrf_token):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        other_workspace = WorkspaceFactory.create()
        session.add(other_workspace)
        session.commit()
        agent = AgentFactory.create()
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
            "workspaces_names": [workspace.name]
        }
        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )
        assert res.status_code == 400

    def test_run_agent_invalid_missing_executor_data(self, csrf_token, session,
                                                    test_client):
        agent = AgentFactory.create()
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token
        }
        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )
        assert res.status_code == 400

    def test_run_agent_invalid_executor_argument(self, session, test_client):
        agent = AgentFactory.create()
        agent.sid = "this_is_a_sid"
        executor = ExecutorFactory.create(agent=agent)
        workspace = WorkspaceFactory.create()

        session.add(executor)
        session.commit()

        payload = {
            'executor_data': {
                "args": {
                    "another_param_name": 'param_content'
                },
                "executor": executor.name
            },
            "workspaces_names": [workspace.name]
        }

        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )

        assert res.status_code == 400

    def test_invalid_body(self, test_client, session):
        agent = AgentFactory.create()
        session.add(agent)
        session.commit()
        res = test_client.post(
            join(self.url(agent), 'run'),
            data='[" broken]"{'
        )
        assert res.status_code == 400

    def test_invalid_content_type(self, test_client, session, csrf_token):
        agent = AgentFactory.create()
        workspace = WorkspaceFactory.create()
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executor_data': {
                "args": {
                    "param1": True
                },
                "executor": "executor_name"
            },
            "workspaces_names": [workspace.name]
        }
        headers = [
            ('content-type', 'text/html'),
        ]
        res = test_client.post(
            join(self.url(agent), 'run'),
            data=payload,
            headers=headers)
        assert res.status_code == 400

    def test_invalid_executor(self, test_client, session, csrf_token):
        agent = AgentFactory.create()
        agent.sid = "this_is_a_sid"
        workspace = WorkspaceFactory.create()
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executor_data': {
                "args": {
                    "param1": True
                },
                "executor": "executor_name"
            },
            "workspaces_names": [workspace.name]
        }
        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )
        assert res.status_code == 400

    def test_happy_path_valid_json(self, test_client, session, csrf_token):
        agent = AgentFactory.create()
        agent.sid = "this_is_a_sid"
        executor = ExecutorFactory.create(agent=agent)
        executor2 = ExecutorFactory.create(agent=agent)
        workspace = WorkspaceFactory.create()

        session.add(executor)
        session.commit()

        assert agent.last_run is None
        assert executor.last_run is None
        assert executor2.last_run is None

        payload = {
            'csrf_token': csrf_token,
            'executor_data': {
                "args": {
                    "param_name": "test"
                },
                "executor": executor.name,
            },
            "workspaces_names": [workspace.name]
        }
        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )
        assert res.status_code == 200
        command_id = res.json["commands_id"]
        command = Command.query.filter(Command.workspace_id == workspace.id).one()
        assert command_id[0] == command.id
        assert agent.last_run is not None
        assert executor.last_run is not None
        assert executor2.last_run is None
        assert agent.last_run == executor.last_run

    def test_invalid_parameter_type(self, test_client, session, csrf_token):
        agent = AgentFactory.create()
        agent.sid = "this_is_a_sid"
        executor = ExecutorFactory.create(agent=agent)
        workspace = WorkspaceFactory.create()

        session.add(executor)
        session.commit()

        payload = {
            'csrf_token': csrf_token,
            'executor_data': {
                "args": {
                    "param_name": ["test"]
                },
                "executor": executor.name
            },
            "workspaces_names": [workspace.name]
        }
        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )
        assert res.status_code == 400

    def test_invalid_json_on_executor_data_breaks_the_api(self, csrf_token,
                                                         session, test_client):
        workspace = WorkspaceFactory.create()
        agent = AgentFactory.create()
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': '[][dassa',
            "workspaces_names": [workspace.name]
        }
        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )
        assert res.status_code == 400

    def test_run_agent(self, session, csrf_token, test_client):
        agent = AgentFactory.create()
        workspace = WorkspaceFactory.create()
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': '',
            "workspaces_names": [workspace.name]
        }
        res = test_client.post(
            join(self.url(agent), 'run'),
            json=payload
        )
        assert res.status_code == 400

    def test_get_manifests(self, session, csrf_token, test_client):
        agent = AgentFactory.create()
        session.add(agent)
        session.commit()
        res = test_client.get(join(self.url(), 'get_manifests'))
        assert "BURP_API_PULL_INTERVAL" in res.json["burp"]["optional_environment_variables"]
        assert "TENABLE_PULL_INTERVAL" in res.json["tenableio"]["optional_environment_variables"]
        assert res.status_code == 200

    @pytest.fixture
    def executors(self, workspace):
        """
        Creates multiple executors with different parameters_metadata structures.
        """
        return [
            factories.ExecutorFactory.create(
                parameters_metadata={
                    "NUCLEI_TARGET": {"base": "list", "type": "list", "mandatory": True},
                    "NUCLEI_EXCLUDE": {"base": "list", "type": "list", "mandatory": False},
                },
            ),
            factories.ExecutorFactory.create(
                parameters_metadata={
                    "TARGET_URL": {"base": "string", "type": "string", "mandatory": True},
                    "NAMED_CONFIGURATION": {"base": "string", "type": "string", "mandatory": False},
                },
            ),
            factories.ExecutorFactory.create(
                parameters_metadata={
                    "TOKEN": {"base": "string", "type": "string", "mandatory": True},
                    "GET_HOTSPOT": {"base": "boolean", "type": "boolean", "mandatory": False},
                    "COMPONENT_KEY": {"base": "string", "type": "string", "mandatory": False},
                },
            ),
            factories.ExecutorFactory.create(
                parameters_metadata={
                    "DAYS_OLD": {"base": "string", "type": "string", "mandatory": True}
                },
            ),
            factories.ExecutorFactory.create(
                parameters_metadata={
                    "SHODAN_QUERY": {"base": "string", "type": "string", "mandatory": True}
                },
            ),
        ]

    @pytest.mark.parametrize("executor_index", [0, 1, 2, 3, 4])
    def test_save_parameters_success(self, test_client, session, executors, executor_index):
        """
        Ensures valid parameters are saved successfully for all executor types.
        """
        executor = executors[executor_index]
        session.add(executor)
        session.commit()

        valid_data = {
            "executor_id": executor.id,
            "parameters_data": {
                "executor_data": {
                    "args": {
                        key: "test_value" if meta["base"] == "string" else True if meta["base"] == "boolean" else [
                            "test_item"]
                        for key, meta in executor.parameters_metadata.items()  # Creates args dynamically based in parameters metadata
                        if meta["mandatory"]
                    }
                }
            },
        }

        response = test_client.post(
            self.url() + '/save_parameters', json=valid_data, content_type="application/json"
        )
        assert response.status_code == 200
        assert response.json["message"] == "Parameters saved successfully"

    def test_save_parameters_data_missing_executor_id(self, test_client, session):
        """Test missing executor_id returns 400."""
        data = {"parameters_data": {"executor_data": {"args": {}}}}
        response = test_client.post(self.url() + '/save_parameters', json=data, content_type="application/json")
        assert response.status_code == 400
        # Unescape HTML entities to check against raw text
        response_text = unescape(response.data.decode('utf-8'))
        assert "Missing 'executor_id'" in response_text

    def test_save_parameters_data_missing_parameters_data(self, test_client, session):
        """Test missing parameters_data returns 400."""
        executor = factories.ExecutorFactory(parameters_metadata={})
        session.add(executor)
        session.commit()

        data = {"executor_id": executor.id}
        response = test_client.post(self.url() + '/save_parameters', json=data, content_type="application/json")
        assert response.status_code == 400
        response_text = unescape(response.data.decode('utf-8'))
        assert "Missing 'parameters_data'" in response_text

    def test_save_parameters_data_invalid_args(self, test_client, session):
        """Test invalid/missing mandatory args in executor_data returns 400."""
        executor = factories.ExecutorFactory(
            parameters_metadata={
                "TARGET": {"base": "list", "type": "list", "mandatory": True},  # Required field
                "OPTION_SC": {"base": "boolean", "type": "boolean", "mandatory": False}
            }
        )
        session.add(executor)
        session.commit()

        data = {
            "executor_id": executor.id,
            "parameters_data": {
                "executor_data": {
                    "args": {
                        "OPTION_SC": 1  # This field should be boolean
                    }
                }
            }
        }
        response = test_client.post(self.url() + '/save_parameters', json=data, content_type="application/json")
        print(response.json)
        assert response.status_code == 400
        assert response.json["errors"]['OPTION_SC'] == 'Expected boolean, got int'
