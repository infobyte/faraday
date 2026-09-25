"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import json
import urllib.parse
from datetime import datetime, timedelta
from unittest import mock

from posixpath import join
from urllib.parse import urljoin
from html import unescape
import pyotp
import pytest

from faraday.server.api.modules.agent import AgentView
from faraday.server.models import Agent, AgentExecution, Command, Executor, db
from tests.factories import (
    AgentFactory,
    AgentExecutionFactory,
    WorkspaceFactory,
    ExecutorFactory,
)
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

    def test_filter_agents(self, test_client, session):
        initial_agent_count = len(session.query(Agent).all())

        agent_names = {
            "FilterTest": 3,
            "FilterTest2": 2,
            "FilterTest3": 1
        }
        agent_list = []

        for agent_name, agent_count in agent_names.items():
            for i in range(agent_count):
                agent = AgentFactory.create()
                agent.name = agent_name
                agent_list.append(agent)
                session.add(agent)
                session.commit()

        final_agent_count = len(session.query(Agent).all())
        assert final_agent_count == initial_agent_count + sum(agent_names.values())

        query_base = '/v3/agents/filter?q={"filters":[{"name":"name","op":"eq","val":">>FILTER<<"}]}'

        for filter_name in agent_names.keys():
            query = query_base.replace(">>FILTER<<", filter_name)
            res = test_client.get(query)
            assert res.status_code == 200
            assert res.json.get("count", 0) == agent_names[filter_name]

    def test_filter_agents_paginates_active_before_inactive(self, test_client, session):
        inactive_1 = AgentFactory.create(active=False, name="ZZZ_inactive")
        active_1 = AgentFactory.create(active=True, name="AAA_active")
        inactive_2 = AgentFactory.create(active=False, name="YYY_inactive")
        active_2 = AgentFactory.create(active=True, name="BBB_active")
        session.commit()

        agent_ids = {inactive_1.id, active_1.id, inactive_2.id, active_2.id}
        query = (
            '/v3/agents/filter?q={"filters":[],"limit":10,"offset":0}'
        )
        res = test_client.get(query)
        assert res.status_code == 200

        rows = [row for row in res.json["rows"] if row["id"] in agent_ids]
        actives = [active_1.id, active_2.id]
        inactives = [inactive_1.id, inactive_2.id]
        active_positions = [i for i, row in enumerate(rows) if row["id"] in actives]
        inactive_positions = [i for i, row in enumerate(rows) if row["id"] in inactives]

        assert active_positions, "expected at least one active agent in the page"
        assert inactive_positions, "expected at least one inactive agent in the page"
        assert max(active_positions) < min(inactive_positions)

    def test_filter_agents_pagination_no_skip_or_duplicate_with_sid_ties(self, test_client, session):
        # Regression test: several active-but-offline agents (sid=None) tie on every
        # ordering criterion except id. Without an id tiebreaker, paging through them
        # while an unrelated column changes between requests can skip or duplicate rows.
        tied_agents = [
            AgentFactory.create(active=True, sid=None, name=f"tied_agent_{i}")
            for i in range(6)
        ]
        session.commit()

        def fetch_page(offset):
            q = json.dumps({
                "filters": [{"name": "name", "op": "contains", "val": "tied_agent_"}],
                "limit": 2,
                "offset": offset,
            })
            res = test_client.get(f'/v3/agents/filter?q={urllib.parse.quote(q)}')
            assert res.status_code == 200
            return [row["id"] for row in res.json["rows"]]

        page1 = fetch_page(0)
        # Mutate an unrelated column on an already-seen agent between page requests,
        # simulating the concurrent update from the reported regression.
        tied_agents[0].name = "tied_agent_0_renamed"
        session.commit()
        page2 = fetch_page(2)
        page3 = fetch_page(4)

        all_ids = page1 + page2 + page3
        assert len(all_ids) == len(set(all_ids)), "pagination duplicated a runner"
        assert set(all_ids) == {a.id for a in tied_agents}, "pagination skipped a runner"

    def test_filter_agents_respects_client_order_by(self, test_client, session):
        # Regression test: a client-provided order_by must not be silently overridden
        # by the internal "active first, online first" defaults.
        agent_c = AgentFactory.create(active=True, sid="sid_3", name="orderby_test_CCC")
        agent_b = AgentFactory.create(active=False, sid=None, name="orderby_test_BBB")
        agent_a = AgentFactory.create(active=True, sid="sid_1", name="orderby_test_AAA")
        session.commit()

        q = json.dumps({
            "filters": [{"name": "name", "op": "contains", "val": "orderby_test_"}],
            "order_by": [{"field": "name", "direction": "asc"}],
            "limit": 10,
            "offset": 0,
        })
        res = test_client.get(f'/v3/agents/filter?q={urllib.parse.quote(q)}')
        assert res.status_code == 200
        ids = [row["id"] for row in res.json["rows"]]
        # agent_b is inactive but sorts second by name — active is not forced to the front
        # when the client asks for an explicit order.
        assert ids == [agent_a.id, agent_b.id, agent_c.id]

    def test_filter_agents_active_and_sid_break_ties_in_client_order_by(self, test_client, session):
        # active/sid are appended as tiebreakers after the client's requested field,
        # so ties on that field still resolve active-first, online-first.
        inactive_tied = AgentFactory.create(active=False, sid=None, name="tied_orderby_name")
        offline_active_tied = AgentFactory.create(active=True, sid=None, name="tied_orderby_name")
        online_active_tied = AgentFactory.create(active=True, sid="tied_session", name="tied_orderby_name")
        session.commit()

        q = json.dumps({
            "filters": [{"name": "name", "op": "contains", "val": "tied_orderby_name"}],
            "order_by": [{"field": "name", "direction": "asc"}],
            "limit": 10,
            "offset": 0,
        })
        res = test_client.get(f'/v3/agents/filter?q={urllib.parse.quote(q)}')
        assert res.status_code == 200
        ids = [row["id"] for row in res.json["rows"]]
        assert ids == [online_active_tied.id, offline_active_tied.id, inactive_tied.id]

    def test_filter_agents_pagination_limit_two_is_disjoint_and_active_first(self, test_client, session):
        actives = [
            AgentFactory.create(active=True, sid=None, name=f"page_active_{i}")
            for i in range(4)
        ]
        inactives = [
            AgentFactory.create(active=False, name=f"page_inactive_{i}")
            for i in range(2)
        ]
        session.commit()

        created_ids = {a.id for a in actives} | {a.id for a in inactives}

        def fetch_page(offset):
            q = json.dumps({
                "filters": [{"name": "name", "op": "contains", "val": "page_"}],
                "limit": 2,
                "offset": offset,
            })
            res = test_client.get(f'/v3/agents/filter?q={urllib.parse.quote(q)}')
            assert res.status_code == 200
            return [row["id"] for row in res.json["rows"]]

        pages = [fetch_page(offset) for offset in (0, 2, 4)]
        all_ids = [agent_id for page in pages for agent_id in page]

        assert len(all_ids) == len(set(all_ids)), "pagination duplicated a runner"
        assert set(all_ids) == created_ids, "pagination skipped a runner"

        active_ids = {a.id for a in actives}
        inactive_ids = {a.id for a in inactives}
        active_positions = [i for i, agent_id in enumerate(all_ids) if agent_id in active_ids]
        inactive_positions = [i for i, agent_id in enumerate(all_ids) if agent_id in inactive_ids]
        assert active_positions and inactive_positions
        assert max(active_positions) < min(inactive_positions)

    def test_filter_agents_paginates_online_before_offline_within_active(self, test_client, session):
        offline_active = AgentFactory.create(active=True, sid=None, name="online_test_wordpress-runner-06")
        online_active_1 = AgentFactory.create(active=True, sid="session_a", name="online_test_AAA_online")
        online_active_2 = AgentFactory.create(active=True, sid="session_b", name="online_test_ZZZ_online")
        inactive = AgentFactory.create(active=False, name="online_test_inactive_agent")
        session.commit()

        q = json.dumps({
            "filters": [{"name": "name", "op": "contains", "val": "online_test_"}],
            "limit": 10,
            "offset": 0,
        })
        res = test_client.get(f'/v3/agents/filter?q={urllib.parse.quote(q)}')
        assert res.status_code == 200

        rows = res.json["rows"]
        online_ids = [online_active_1.id, online_active_2.id]
        offline_active_ids = [offline_active.id]
        inactive_ids = [inactive.id]

        online_positions = [i for i, row in enumerate(rows) if row["id"] in online_ids]
        offline_active_positions = [i for i, row in enumerate(rows) if row["id"] in offline_active_ids]
        inactive_positions = [i for i, row in enumerate(rows) if row["id"] in inactive_ids]

        assert online_positions and offline_active_positions and inactive_positions
        assert max(online_positions) < min(offline_active_positions)
        assert max(offline_active_positions) < min(inactive_positions)

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

    def test_bulk_delete_agents(self, test_client, session):
        agent_1 = AgentFactory.create()
        agent_2 = AgentFactory.create()
        session.commit()
        ids = [agent_1.id, agent_2.id]

        response = test_client.delete(self.url(), data={'ids': ids})

        assert response.status_code == 200
        assert response.json['deleted'] == 2
        assert session.query(Agent).filter(Agent.id.in_(ids)).count() == 0

    def test_bulk_delete_agents_without_ids(self, test_client):
        response = test_client.delete(self.url(), data={'agents_ids': []})
        assert response.status_code == 400

    def test_bulk_delete_agents_invalid_characters(self, test_client):
        response = test_client.delete(self.url(), data={'ids': [-1, 'test']})
        assert response.json['deleted'] == 0

    def test_bulk_delete_agents_with_executors(self, test_client, session):
        agent = AgentFactory.create()
        executor = ExecutorFactory.create(agent=agent)
        session.commit()
        agent_id = agent.id
        executor_id = executor.id

        response = test_client.delete(self.url(), data={'ids': [agent_id]})

        assert response.status_code == 200
        assert response.json['deleted'] == 1
        assert session.query(Agent).filter(Agent.id == agent_id).count() == 0
        assert session.query(Executor).filter(Executor.id == executor_id).count() == 0

    def test_bulk_delete_agents_with_execution_logs(self, test_client, session):
        agent = AgentFactory.create()
        executor = ExecutorFactory.create(agent=agent)
        execution = AgentExecutionFactory.create(executor=executor)
        session.commit()
        agent_id = agent.id
        executor_id = executor.id
        execution_id = execution.id

        response = test_client.delete(self.url(), data={'ids': [agent_id]})

        assert response.status_code == 200
        assert response.json['deleted'] == 1
        assert session.query(Agent).filter(Agent.id == agent_id).count() == 0
        assert session.query(Executor).filter(Executor.id == executor_id).count() == 0
        assert session.query(AgentExecution).filter(
            AgentExecution.id == execution_id).count() == 0

    def _bulk_delete_q(self, *filters):
        q = json.dumps({"filters": list(filters)})
        return f'{self.url()}?q={urllib.parse.quote(q)}'

    def test_bulk_delete_by_filter_status_online(self, test_client, session):
        online_1 = AgentFactory.create(sid="session_a")
        online_2 = AgentFactory.create(sid="session_b")
        offline = AgentFactory.create(sid=None)
        session.commit()

        res = test_client.delete(self._bulk_delete_q({"name": "status", "op": "eq", "val": "online"}))

        assert res.status_code == 200
        assert session.query(Agent).filter(Agent.id.in_([online_1.id, online_2.id])).count() == 0
        assert session.query(Agent).filter(Agent.id == offline.id).count() == 1

    def test_bulk_delete_by_filter_status_offline(self, test_client, session):
        online = AgentFactory.create(sid="active_session")
        offline = AgentFactory.create(sid=None)
        session.commit()

        res = test_client.delete(self._bulk_delete_q({"name": "status", "op": "eq", "val": "offline"}))

        assert res.status_code == 200
        assert session.query(Agent).filter(Agent.id == offline.id).count() == 0
        assert session.query(Agent).filter(Agent.id == online.id).count() == 1

    def test_bulk_delete_by_filter_tools(self, test_client, session):
        agent_match = AgentFactory.create()
        ExecutorFactory.create(agent=agent_match, name="nmap")
        agent_no_match = AgentFactory.create()
        session.commit()

        res = test_client.delete(self._bulk_delete_q({"name": "tools", "op": "eq", "val": "nmap"}))

        assert res.status_code == 200
        assert session.query(Agent).filter(Agent.id == agent_match.id).count() == 0
        assert session.query(Agent).filter(Agent.id == agent_no_match.id).count() == 1

    def test_bulk_delete_by_filter_blocked(self, test_client, session):
        blocked = AgentFactory.create(active=False)
        unblocked = AgentFactory.create(active=True)
        session.commit()

        res = test_client.delete(self._bulk_delete_q({"name": "blocked", "op": "eq", "val": "true"}))

        assert res.status_code == 200
        assert session.query(Agent).filter(Agent.id == blocked.id).count() == 0
        assert session.query(Agent).filter(Agent.id == unblocked.id).count() == 1

    def _filter_q(self, *filters):
        q = json.dumps({"filters": list(filters)})
        return f'/v3/agents/filter?q={urllib.parse.quote(q)}'

    def test_filter_by_status_online(self, test_client, session):
        online = AgentFactory.create(sid="active_session")
        offline = AgentFactory.create(sid=None)
        session.commit()

        res = test_client.get(self._filter_q({"name": "status", "op": "eq", "val": "online"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert online.id in ids
        assert offline.id not in ids

    def test_filter_by_status_offline(self, test_client, session):
        online = AgentFactory.create(sid="active_session")
        offline = AgentFactory.create(sid=None)
        session.commit()

        res = test_client.get(self._filter_q({"name": "status", "op": "eq", "val": "offline"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert offline.id in ids
        assert online.id not in ids

    def test_filter_by_tools_eq(self, test_client, session):
        agent_with = AgentFactory.create()
        ExecutorFactory.create(agent=agent_with, name="nmap")
        agent_without = AgentFactory.create()
        session.commit()

        res = test_client.get(self._filter_q({"name": "tools", "op": "eq", "val": "nmap"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_with.id in ids
        assert agent_without.id not in ids

    def test_filter_by_tools_ne(self, test_client, session):
        agent_nmap = AgentFactory.create()
        ExecutorFactory.create(agent=agent_nmap, name="nmap")
        agent_burp = AgentFactory.create()
        ExecutorFactory.create(agent=agent_burp, name="burp")
        session.commit()

        res = test_client.get(self._filter_q({"name": "tools", "op": "ne", "val": "nmap"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_burp.id in ids
        assert agent_nmap.id not in ids

    def test_filter_by_tools_contains(self, test_client, session):
        agent_match = AgentFactory.create()
        ExecutorFactory.create(agent=agent_match, name="nmap_scanner")
        agent_no_match = AgentFactory.create()
        ExecutorFactory.create(agent=agent_no_match, name="burp")
        session.commit()

        res = test_client.get(self._filter_q({"name": "tools", "op": "like", "val": "nmap"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_match.id in ids
        assert agent_no_match.id not in ids

    def test_filter_by_last_execution_date_le(self, test_client, session):
        now = datetime.utcnow()
        agent_old = AgentFactory.create()
        ex_old = ExecutorFactory.create(agent=agent_old)
        ex_old.last_run = now - timedelta(days=10)

        agent_new = AgentFactory.create()
        ex_new = ExecutorFactory.create(agent=agent_new)
        ex_new.last_run = now - timedelta(days=1)
        session.commit()

        cutoff = (now - timedelta(days=5)).isoformat()
        res = test_client.get(self._filter_q({"name": "last_execution_date", "op": "le", "val": cutoff}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_old.id in ids
        assert agent_new.id not in ids

    def test_filter_by_last_execution_tool(self, test_client, session):
        now = datetime.utcnow()
        agent = AgentFactory.create()
        ex_first = ExecutorFactory.create(agent=agent, name="nmap")
        ex_first.last_run = now - timedelta(hours=2)
        ex_last = ExecutorFactory.create(agent=agent, name="burp")
        ex_last.last_run = now - timedelta(hours=1)

        agent_other = AgentFactory.create()
        ex_nmap = ExecutorFactory.create(agent=agent_other, name="nmap")
        ex_nmap.last_run = now - timedelta(hours=1)
        session.commit()

        # "burp" ran last on agent; only agent should match
        res = test_client.get(self._filter_q({"name": "last_execution_tool", "op": "eq", "val": "burp"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent.id in ids
        assert agent_other.id not in ids

    def test_filter_by_last_execution_tool_contains(self, test_client, session):
        now = datetime.utcnow()
        agent = AgentFactory.create()
        ex_first = ExecutorFactory.create(agent=agent, name="nmap_scanner")
        ex_first.last_run = now - timedelta(hours=2)
        ex_last = ExecutorFactory.create(agent=agent, name="burp_suite")
        ex_last.last_run = now - timedelta(hours=1)

        agent_other = AgentFactory.create()
        ex_nmap = ExecutorFactory.create(agent=agent_other, name="nmap_scanner")
        ex_nmap.last_run = now - timedelta(hours=1)
        session.commit()

        # "burp" ran last on agent; contains "burp" should match only agent
        res = test_client.get(self._filter_q({"name": "last_execution_tool", "op": "contains", "val": "burp"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent.id in ids
        assert agent_other.id not in ids

        # "nmap" ran last on agent_other; contains "nmap" should match only agent_other
        res = test_client.get(self._filter_q({"name": "last_execution_tool", "op": "contains", "val": "nmap"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_other.id in ids
        assert agent.id not in ids

    def test_filter_by_category_eq(self, test_client, session):
        agent_web = AgentFactory.create()
        ex_web = ExecutorFactory.create(agent=agent_web)
        ex_web.category = ["web", "network"]

        agent_mobile = AgentFactory.create()
        ex_mobile = ExecutorFactory.create(agent=agent_mobile)
        ex_mobile.category = ["mobile"]
        session.commit()

        res = test_client.get(self._filter_q({"name": "category", "op": "eq", "val": "web"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_web.id in ids
        assert agent_mobile.id not in ids

    def test_filter_by_category_is_not_one_of(self, test_client, session):
        agent_web = AgentFactory.create()
        ex_web = ExecutorFactory.create(agent=agent_web)
        ex_web.category = ["web"]

        agent_network = AgentFactory.create()
        ex_network = ExecutorFactory.create(agent=agent_network)
        ex_network.category = ["network"]
        session.commit()

        res = test_client.get(self._filter_q({"name": "category", "op": "is_not_one_of", "val": "web"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_network.id in ids
        assert agent_web.id not in ids

    def test_filter_by_blocked_true(self, test_client, session):
        active = AgentFactory.create(active=True)
        blocked = AgentFactory.create(active=False)
        session.commit()

        res = test_client.get(self._filter_q({"name": "blocked", "op": "eq", "val": "true"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert blocked.id in ids
        assert active.id not in ids

    def test_filter_by_blocked_false(self, test_client, session):
        active = AgentFactory.create(active=True)
        blocked = AgentFactory.create(active=False)
        session.commit()

        res = test_client.get(self._filter_q({"name": "blocked", "op": "eq", "val": "false"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert active.id in ids
        assert blocked.id not in ids

    def test_filter_by_blocked_ne(self, test_client, session):
        active = AgentFactory.create(active=True)
        blocked = AgentFactory.create(active=False)
        session.commit()

        res = test_client.get(self._filter_q({"name": "blocked", "op": "ne", "val": "true"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert active.id in ids
        assert blocked.id not in ids

    def test_filter_by_name_contains(self, test_client, session):
        agent_match = AgentFactory.create(name="nmap_agent")
        agent_no_match = AgentFactory.create(name="burp_agent")
        session.commit()

        res = test_client.get(self._filter_q({"name": "name", "op": "contains", "val": "nmap"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_match.id in ids
        assert agent_no_match.id not in ids

    def test_filter_by_description_contains(self, test_client, session):
        agent_match = AgentFactory.create(description="scans open ports")
        agent_no_match = AgentFactory.create(description="web vulnerability scanner")
        session.commit()

        res = test_client.get(self._filter_q({"name": "description", "op": "contains", "val": "open ports"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_match.id in ids
        assert agent_no_match.id not in ids

    def test_filter_by_tools_is_one_of(self, test_client, session):
        agent_nmap = AgentFactory.create()
        ExecutorFactory.create(agent=agent_nmap, tool="nmap")
        agent_burp = AgentFactory.create()
        ExecutorFactory.create(agent=agent_burp, tool="burp")
        agent_other = AgentFactory.create()
        ExecutorFactory.create(agent=agent_other, tool="zap")
        session.commit()

        res = test_client.get(self._filter_q({"name": "tools", "op": "is_one_of", "val": ["nmap", "burp"]}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_nmap.id in ids
        assert agent_burp.id in ids
        assert agent_other.id not in ids

    def test_filter_by_tools_is_not_one_of(self, test_client, session):
        agent_nmap = AgentFactory.create()
        ExecutorFactory.create(agent=agent_nmap, tool="nmap")
        agent_burp = AgentFactory.create()
        ExecutorFactory.create(agent=agent_burp, tool="burp")
        agent_other = AgentFactory.create()
        ExecutorFactory.create(agent=agent_other, tool="zap")
        session.commit()

        res = test_client.get(self._filter_q({"name": "tools", "op": "is_not_one_of", "val": ["nmap", "burp"]}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_other.id in ids
        assert agent_nmap.id not in ids
        assert agent_burp.id not in ids

    def test_filter_by_category_is_one_of(self, test_client, session):
        agent_web = AgentFactory.create()
        ex_web = ExecutorFactory.create(agent=agent_web)
        ex_web.category = ["web"]

        agent_network = AgentFactory.create()
        ex_network = ExecutorFactory.create(agent=agent_network)
        ex_network.category = ["network"]

        agent_mobile = AgentFactory.create()
        ex_mobile = ExecutorFactory.create(agent=agent_mobile)
        ex_mobile.category = ["mobile"]
        session.commit()

        res = test_client.get(self._filter_q({"name": "category", "op": "is_one_of", "val": ["web", "network"]}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert agent_web.id in ids
        assert agent_network.id in ids
        assert agent_mobile.id not in ids
