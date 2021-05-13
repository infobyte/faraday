"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from unittest import mock

from posixpath import join as urljoin
import pyotp
import pytest

from faraday.server.api.modules.agent import AgentWithWorkspacesView, AgentView
from faraday.server.models import Agent, Command
from tests.factories import AgentFactory, WorkspaceFactory, ExecutorFactory
from tests.test_api_non_workspaced_base import ReadWriteAPITests, PatchableTestsMixin
from tests.test_api_workspaced_base import ReadOnlyMultiWorkspacedAPITests
from tests import factories
from tests.test_api_workspaced_base import API_PREFIX
from tests.utils.url import v2_to_v3


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


def get_raw_agent(name="My agent", active=None, token=None, workspaces=None):
    raw_agent = {}
    if name is not None:
        raw_agent["name"] = name
    if active is not None:
        raw_agent["active"] = active
    if token:
        raw_agent["token"] = token
    if workspaces is not None:
        raw_agent["workspaces"] = [
            workspace.name for workspace in workspaces
        ]
    return raw_agent


@pytest.mark.usefixtures('logged_user')
class TestAgentAuthTokenAPIGeneric:

    def check_url(self, url):
        return url

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_get_agent_token(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_registration_secret = None
        res = test_client.get(self.check_url('/v2/agent_token/'))
        assert 'token' in res.json and 'expires_in' in res.json
        assert len(res.json['token'])

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_token_fails(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_registration_secret = None
        res = test_client.post(self.check_url('/v2/agent_token/'))
        assert res.status_code == 405


@pytest.mark.usefixtures('logged_user')
class TestAgentAuthTokenAPIGenericV3(TestAgentAuthTokenAPIGeneric):
    def check_url(self, url):
        return v2_to_v3(url)


class TestAgentCreationAPI:

    def check_url(self, url):
        return url

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_create_agent_valid_token(self, faraday_server_config, test_client,
                                      session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        other_workspace = WorkspaceFactory.create()
        session.add(other_workspace)
        session.commit()
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        faraday_server_config.agent_token_expiration = 60
        logout(test_client, [302])
        initial_agent_count = len(session.query(Agent).all())
        raw_data = get_raw_agent(
            name='new_agent',
            token=pyotp.TOTP(secret, interval=60).now(),
            workspaces=[workspace, other_workspace]
        )
        # /v2/agent_registration/
        res = test_client.post(self.check_url('/v2/agent_registration/'), data=raw_data)
        assert res.status_code == 201, (res.json, raw_data)
        assert len(session.query(Agent).all()) == initial_agent_count + 1
        assert workspace.name in res.json['workspaces']
        assert other_workspace.name in res.json['workspaces']
        assert len(res.json['workspaces']) == 2
        workspaces = Agent.query.get(res.json['id']).workspaces
        assert len(workspaces) == 2
        assert workspace in workspaces
        assert other_workspace in workspaces

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_without_name_fails(self, faraday_server_config,
                                             test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        session.commit()
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        faraday_server_config.agent_token_expiration = 60
        logout(test_client, [302])
        initial_agent_count = len(session.query(Agent).all())
        raw_data = get_raw_agent(
            name=None,
            token=pyotp.TOTP(secret, interval=60).now(),
            workspaces=[workspace]
        )
        # /v2/agent_registration/
        res = test_client.post(
            self.check_url('/v2/agent_registration/'),
            data=raw_data
        )
        assert res.status_code == 400
        assert len(session.query(Agent).all()) == initial_agent_count

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_invalid_token(self, faraday_server_config,
                                        test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        session.commit()
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        logout(test_client, [302])
        raw_data = get_raw_agent(
            token="INVALID",
            name="test agent",
            workspaces=[workspace]
        )
        # /v2/agent_registration/
        res = test_client.post(self.check_url('/v2/agent_registration/'), data=raw_data)
        assert res.status_code == 401

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_agent_token_not_set(self, faraday_server_config,
                                              test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        session.commit()
        faraday_server_config.agent_registration_secret = None
        logout(test_client, [302])
        raw_data = get_raw_agent(
            name="test agent",
            workspaces=[workspace],
        )
        # /v2/agent_registration/
        res = test_client.post(self.check_url('/v2/agent_registration/'), data=raw_data)
        assert res.status_code == 400

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_invalid_payload(self, faraday_server_config,
                                          test_client, session):
        faraday_server_config.agent_registration_secret = None
        logout(test_client, [302])
        raw_data = {"PEPE": 'INVALID'}
        # /v2/agent_registration/
        res = test_client.post(self.check_url('/v2/agent_registration/'), data=raw_data)
        assert res.status_code == 400

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_empty_workspaces(self, faraday_server_config,
                                           test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        session.commit()
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        faraday_server_config.agent_token_expiration = 60
        logout(test_client, [302])
        raw_data = get_raw_agent(
            token=pyotp.TOTP(secret, interval=60).now(),
            name="test agent",
            workspaces=[]
        )
        # /v2/agent_registration/
        res = test_client.post(self.check_url('/v2/agent_registration/'), data=raw_data)
        assert res.status_code == 400

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_inexistent_workspaces(self, faraday_server_config,
                                                test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        session.commit()
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        faraday_server_config.agent_token_expiration = 60
        logout(test_client, [302])
        raw_data = get_raw_agent(
            token=pyotp.TOTP(secret, interval=60).now(),
            name="test agent",
            workspaces=[]
        )
        raw_data["workspaces"] = ["donotexist"]
        # /v2/agent_registration/
        res = test_client.post(self.check_url('/v2/agent_registration/'), data=raw_data)
        assert res.status_code == 404

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_workspaces_not_set(self, faraday_server_config,
                                             test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        session.commit()
        secret = pyotp.random_base32()
        faraday_server_config.agent_registration_secret = secret
        faraday_server_config.agent_token_expiration = 60
        logout(test_client, [302])
        raw_data = get_raw_agent(
            name="test agent",
            token=pyotp.TOTP(secret, interval=60).now()
        )
        # /v2/agent_registration/
        res = test_client.post(self.check_url('/v2/agent_registration/'), data=raw_data)
        assert res.status_code == 400


class TestAgentCreationAPIV3(TestAgentCreationAPI):
    def check_url(self, url):
        return v2_to_v3(url)


class TestAgentWithWorkspacesAPIGeneric(ReadWriteAPITests):
    model = Agent
    factory = factories.AgentFactory
    view_class = AgentWithWorkspacesView
    api_endpoint = 'agents'
    patchable_fields = ['name']

    def test_create_succeeds(self, test_client):
        with pytest.raises(AssertionError) as exc_info:
            super().test_create_succeeds(test_client)
        assert '405' in exc_info.value.args[0]

    def test_create_fails_with_empty_dict(self, test_client):
        with pytest.raises(AssertionError) as exc_info:
            super().test_create_fails_with_empty_dict(test_client)
        assert '405' in exc_info.value.args[0]

    def workspaced_url(self, workspace, obj=None):
        url = API_PREFIX + workspace.name + '/' + self.api_endpoint + '/'
        if obj is not None:
            id_ = str(obj.id) if isinstance(obj, self.model) else str(obj)
            url += id_ + u'/'
        return url

    def create_raw_agent(self, active=False, token="TOKEN",
                         workspaces=None):
        return get_raw_agent(name="My agent", token=token, active=active,
                             workspaces=workspaces)

    def test_create_agent_invalid(self, test_client, session):
        """
            To create new agent use the
            <Rule '/v2/agent_registration/' (POST, OPTIONS)
        """
        initial_agent_count = len(session.query(Agent).all())
        raw_agent = self.create_raw_agent()
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 405  # the only way to create agents is by using the token!
        assert len(session.query(Agent).all()) == initial_agent_count

    def test_get_not_workspaced(self, test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        agent = AgentFactory.create(workspaces=[workspace], active=True)
        session.commit()
        res = test_client.get(self.url(agent))
        assert res.status_code == 200
        assert len(res.json['workspaces']) == 1
        assert workspace.name in res.json['workspaces'][0]

    def test_update_agent(self, test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        agent = AgentFactory.create(workspaces=[workspace], active=True)
        session.commit()
        raw_agent = self.create_raw_agent(active=False, workspaces=[workspace])
        res = test_client.put(self.url(agent.id), data=raw_agent)
        assert res.status_code == 200, (res.json, raw_agent)
        assert not res.json['active']
        assert len(res.json['workspaces']) == 1
        assert workspace.name in res.json['workspaces'][0]

    def test_update_agent_add_a_workspace(self, test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        other_workspace = WorkspaceFactory.create()
        session.add(other_workspace)
        agent = AgentFactory.create(workspaces=[workspace],
                                    active=True)
        session.commit()
        raw_agent = self.create_raw_agent(
            workspaces=[workspace, other_workspace]
        )
        res = test_client.put(self.url(agent.id), data=raw_agent)
        assert res.status_code == 200
        assert other_workspace.name in res.json['workspaces']
        assert workspace.name in res.json['workspaces']
        assert len(res.json['workspaces']) == 2
        workspaces = Agent.query.get(agent.id).workspaces
        assert len(workspaces) == 2
        assert workspace in workspaces
        assert other_workspace in workspaces

    def test_update_agent_add_a_inexistent_workspace(self, test_client,
                                                     session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        other_workspace = WorkspaceFactory.create()
        session.add(other_workspace)
        agent = AgentFactory.create(workspaces=[workspace],
                                    active=True)
        session.commit()
        raw_agent = self.create_raw_agent(
            workspaces=[workspace, other_workspace]
        )
        raw_agent["workspaces"] = ["donotexist"]
        res = test_client.put(self.url(agent.id), data=raw_agent)
        assert res.status_code == 404
        workspaces = Agent.query.get(agent.id).workspaces
        assert len(workspaces) == 1
        assert workspace in workspaces

    def test_update_agent_delete_a_workspace(self, test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        other_workspace = WorkspaceFactory.create()
        session.add(other_workspace)
        agent = AgentFactory.create(workspaces=[workspace, other_workspace],
                                    active=True)
        session.commit()
        raw_agent = self.create_raw_agent(workspaces=[workspace])
        res = test_client.put(self.url(agent.id), data=raw_agent)
        assert res.status_code == 200
        assert len(res.json['workspaces']) == 1
        assert other_workspace.name not in res.json['workspaces']
        assert workspace.name in res.json['workspaces']
        workspaces = Agent.query.get(agent.id).workspaces
        assert len(workspaces) == 1
        assert workspaces[0] == workspace

    def test_update_bug_case(self, test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        agent = AgentFactory.create(workspaces=[workspace])
        session.add(agent)
        session.commit()
        update_data = {
            "id": 1,
            "name": "Agent test",
            "is_online": True,
            "workspaces": [workspace.name]
        }
        res = test_client.put(self.url(agent.id), data=update_data)
        assert res.status_code == 200, (res.json, update_data)
        assert workspace.name in res.json['workspaces']
        assert len(res.json['workspaces']) == 1

    def test_delete_agent(self, test_client, session):
        initial_agent_count = len(session.query(Agent).all())
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        agent = AgentFactory.create(workspaces=[workspace])
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
        agent = AgentFactory.create(
            workspaces=[workspace, other_workspace]
        )
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
        res = test_client.post(
            self.url(agent) + 'run/',
            json=payload
        )
        assert res.status_code == 404


class TestAgentWithWorkspacesAPIGenericV3(TestAgentWithWorkspacesAPIGeneric, PatchableTestsMixin):
    def url(self, obj=None):
        return v2_to_v3(super().url(obj))


class TestAgentAPI(ReadOnlyMultiWorkspacedAPITests):
    model = Agent
    factory = factories.AgentFactory
    view_class = AgentView
    api_endpoint = 'agents'

    def check_url(self, url):
        return url

    def test_get_workspaced(self, test_client, session):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
        agent = AgentFactory.create(workspaces=[self.workspace], active=True)
        session.commit()
        res = test_client.get(self.url(agent))
        assert res.status_code == 200
        assert 'workspaces' not in res.json

    def test_get_workspaced_other_fails(self, test_client, session):
        other_workspace = WorkspaceFactory.create()
        session.add(other_workspace)
        agent = AgentFactory.create(workspaces=[other_workspace], active=True)
        session.commit()
        res = test_client.get(self.url(agent))
        assert res.status_code == 404

    def test_workspaced_delete(self, session, test_client):
        initial_agent_count = len(session.query(Agent).all())
        other_workspace = WorkspaceFactory.create()
        session.add(other_workspace)
        agent = AgentFactory.create(
            workspaces=[self.workspace, other_workspace]
        )
        session.commit()
        assert len(session.query(Agent).all()) == initial_agent_count + 1
        res = test_client.delete(self.url(agent.id))
        assert res.status_code == 204
        assert len(session.query(Agent).all()) == initial_agent_count + 1
        res = test_client.delete(self.url(agent.id))
        assert res.status_code == 404
        res = test_client.get(self.url(agent.id))
        assert res.status_code == 404
        workspaces = Agent.query.get(agent.id).workspaces
        assert len(workspaces) == 1
        assert other_workspace in workspaces

    def test_run_agent_invalid_missing_executorData(self, csrf_token, session,
                                                    test_client):
        agent = AgentFactory.create(workspaces=[self.workspace])
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token
        }
        res = test_client.post(
            self.check_url(urljoin(self.url(agent), 'run/')),
            json=payload
        )
        assert res.status_code == 400

    def test_invalid_body(self, test_client, session):
        agent = AgentFactory.create(workspaces=[self.workspace])
        session.add(agent)
        session.commit()
        res = test_client.post(
            self.check_url(urljoin(self.url(agent), 'run/')),
            data='[" broken]"{'
        )
        assert res.status_code == 400

    def test_invalid_content_type(self, test_client, session, csrf_token):
        agent = AgentFactory.create(workspaces=[self.workspace])
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
            self.check_url(urljoin(self.url(agent), 'run/')),
            data=payload,
            headers=headers)
        assert res.status_code == 400

    def test_invalid_executor(self, test_client, session, csrf_token):
        agent = AgentFactory.create(workspaces=[self.workspace])
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
        res = test_client.post(
            self.check_url(urljoin(self.url(agent), 'run/')),
            json=payload
        )
        assert res.status_code == 400

    def test_happy_path_valid_json(self, test_client, session, csrf_token):
        agent = AgentFactory.create(workspaces=[self.workspace])
        executor = ExecutorFactory.create(agent=agent)
        executor2 = ExecutorFactory.create(agent=agent)

        session.add(executor)
        session.commit()

        assert agent.last_run is None
        assert executor.last_run is None
        assert executor2.last_run is None

        payload = {
            'csrf_token': csrf_token,
            'executorData': {
                "args": {
                    "param_name": "test"
                },
                "executor": executor.name
            },
        }
        res = test_client.post(
            self.check_url(urljoin(self.url(agent), 'run/')),
            json=payload
        )
        assert res.status_code == 200
        command_id = res.json["command_id"]
        command = Command.query.filter(Command.workspace_id == self.workspace.id).one()
        assert command_id == command.id
        assert agent.last_run is not None
        assert executor.last_run is not None
        assert executor2.last_run is None
        assert agent.last_run == executor.last_run

    def test_invalid_parameter_type(self, test_client, session, csrf_token):
        agent = AgentFactory.create(workspaces=[self.workspace])
        executor = ExecutorFactory.create(agent=agent)

        session.add(executor)
        session.commit()

        payload = {
            'csrf_token': csrf_token,
            'executorData': {
                "args": {
                    "param_name": ["test"]
                },
                "executor": executor.name
            },
        }
        res = test_client.post(
            self.check_url(urljoin(self.url(agent), 'run/')),
            json=payload
        )
        assert res.status_code == 400

    def test_invalid_json_on_executorData_breaks_the_api(self, csrf_token,
                                                         session, test_client):
        agent = AgentFactory.create(workspaces=[self.workspace])
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': '[][dassa',
        }
        res = test_client.post(
            self.check_url(urljoin(self.url(agent), 'run/')),
            json=payload
        )
        assert res.status_code == 400

    def test_run_agent(self, session, csrf_token, test_client):
        agent = AgentFactory.create(workspaces=[self.workspace])
        session.add(agent)
        session.commit()
        payload = {
            'csrf_token': csrf_token,
            'executorData': '',
        }
        res = test_client.post(
            self.check_url(urljoin(self.url(agent), 'run/')),
            json=payload
        )
        assert res.status_code == 400


class TestAgentAPIV3(TestAgentAPI):
    def url(self, obj=None, workspace=None):
        return v2_to_v3(super().url(obj, workspace))

    def check_url(self, url):
        return v2_to_v3(url)
