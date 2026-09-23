import json
import urllib.parse
from uuid import uuid4

import pytest

from tests.test_api_non_workspaced_base import ReadOnlyAPITests, BulkDeleteTestsMixin
from faraday.server.models import AgentExecution
from tests import factories
from tests.factories import AgentExecutionFactory, AgentFactory, ExecutorFactory, WorkspaceFactory
from faraday.server.api.modules.agent_execution import AgentExecutionView


class TestAgentExecution(ReadOnlyAPITests, BulkDeleteTestsMixin):

    model = AgentExecution
    factory = factories.AgentExecutionFactory
    view_class = AgentExecutionView
    api_endpoint = 'agent_executions'


@pytest.mark.usefixtures('logged_user')
class TestAgentExecutionFilter:

    def _filter_q(self, *filters):
        q = json.dumps({"filters": list(filters)})
        return f'/v3/agent_executions/filter?q={urllib.parse.quote(q)}'

    def _make_execution(self, session, agent_name=None, triggered_by=None, workspace=None):
        run_uuid = uuid4()
        agent = AgentFactory.create(name=agent_name) if agent_name else AgentFactory.create()
        executor = ExecutorFactory.create(agent=agent)
        ws = workspace or WorkspaceFactory.create()
        kwargs = dict(executor=executor, workspace=ws, run_uuid=run_uuid)
        if triggered_by is not None:
            kwargs['triggered_by'] = triggered_by
        return AgentExecutionFactory.create(**kwargs)

    def test_filter_by_name_eq(self, test_client, session):
        ex_match = self._make_execution(session, agent_name="nmap_agent")
        ex_no_match = self._make_execution(session, agent_name="burp_agent")
        session.commit()

        res = test_client.get(self._filter_q({"name": "name", "op": "eq", "val": "nmap_agent"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert ex_match.id in ids
        assert ex_no_match.id not in ids

    def test_filter_by_name_ne(self, test_client, session):
        ex_match = self._make_execution(session, agent_name="nmap_agent")
        ex_no_match = self._make_execution(session, agent_name="burp_agent")
        session.commit()

        res = test_client.get(self._filter_q({"name": "name", "op": "ne", "val": "burp_agent"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert ex_match.id in ids
        assert ex_no_match.id not in ids

    def test_filter_by_name_contains(self, test_client, session):
        ex_match = self._make_execution(session, agent_name="nmap_scanner")
        ex_no_match = self._make_execution(session, agent_name="burp_agent")
        session.commit()

        res = test_client.get(self._filter_q({"name": "name", "op": "contains", "val": "nmap"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert ex_match.id in ids
        assert ex_no_match.id not in ids

    def test_filter_by_triggered_by_eq(self, test_client, session):
        ex_match = self._make_execution(session, triggered_by="admin")
        ex_no_match = self._make_execution(session, triggered_by="scheduler")
        session.commit()

        res = test_client.get(self._filter_q({"name": "triggered_by", "op": "eq", "val": "admin"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert ex_match.id in ids
        assert ex_no_match.id not in ids

    def test_filter_by_triggered_by_contains(self, test_client, session):
        ex_match = self._make_execution(session, triggered_by="admin_user")
        ex_no_match = self._make_execution(session, triggered_by="scheduler")
        session.commit()

        res = test_client.get(self._filter_q({"name": "triggered_by", "op": "contains", "val": "admin"}))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert ex_match.id in ids
        assert ex_no_match.id not in ids

    def test_filter_by_workspaces_is_one_of(self, test_client, session):
        ws_a = WorkspaceFactory.create(name="workspace_alpha")
        ws_b = WorkspaceFactory.create(name="workspace_beta")
        ws_c = WorkspaceFactory.create(name="workspace_gamma")
        ex_a = self._make_execution(session, workspace=ws_a)
        ex_b = self._make_execution(session, workspace=ws_b)
        ex_c = self._make_execution(session, workspace=ws_c)
        session.commit()

        res = test_client.get(self._filter_q({
            "name": "workspaces", "op": "is_one_of", "val": ["workspace_alpha", "workspace_beta"]
        }))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert ex_a.id in ids
        assert ex_b.id in ids
        assert ex_c.id not in ids

    def test_filter_by_workspaces_is_not_one_of(self, test_client, session):
        ws_a = WorkspaceFactory.create(name="workspace_alpha")
        ws_b = WorkspaceFactory.create(name="workspace_beta")
        ws_c = WorkspaceFactory.create(name="workspace_gamma")
        ex_a = self._make_execution(session, workspace=ws_a)
        ex_b = self._make_execution(session, workspace=ws_b)
        ex_c = self._make_execution(session, workspace=ws_c)
        session.commit()

        res = test_client.get(self._filter_q({
            "name": "workspaces", "op": "is_not_one_of", "val": ["workspace_alpha", "workspace_beta"]
        }))
        assert res.status_code == 200
        ids = {r['id'] for r in res.json['rows']}
        assert ex_c.id in ids
        assert ex_a.id not in ids
        assert ex_b.id not in ids

    def _bulk_delete_url(self, *filters):
        q = json.dumps({"filters": list(filters)})
        return f'/v3/agent_executions?q={urllib.parse.quote(q)}'

    def test_bulk_delete_by_filter_name(self, test_client, session):
        ex_match = self._make_execution(session, agent_name="target_agent")
        ex_no_match = self._make_execution(session, agent_name="other_agent")
        session.commit()

        res = test_client.delete(self._bulk_delete_url({"name": "name", "op": "eq", "val": "target_agent"}))

        assert res.status_code == 200
        assert AgentExecution.query.filter_by(id=ex_match.id).count() == 0
        assert AgentExecution.query.filter_by(id=ex_no_match.id).count() == 1

    def test_bulk_delete_by_filter_workspaces(self, test_client, session):
        ws_target = factories.WorkspaceFactory.create(name="ae_target_ws")
        ws_other = factories.WorkspaceFactory.create(name="ae_other_ws")
        ex_match = self._make_execution(session, workspace=ws_target)
        ex_no_match = self._make_execution(session, workspace=ws_other)
        session.commit()

        res = test_client.delete(self._bulk_delete_url({
            "name": "workspaces", "op": "is_one_of", "val": ["ae_target_ws"]
        }))

        assert res.status_code == 200
        assert AgentExecution.query.filter_by(id=ex_match.id).count() == 0
        assert AgentExecution.query.filter_by(id=ex_no_match.id).count() == 1
