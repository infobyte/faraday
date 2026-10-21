"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import datetime
import json

import pytest

from faraday.server.extensions import socketio
from faraday.server.models import AgentExecution
from faraday.server.websockets.dispatcher import DispatcherNamespace
from tests.factories import AgentExecutionFactory, AgentFactory, ExecutorFactory


@pytest.fixture
def dispatcher():
    return DispatcherNamespace('/dispatcher')


@pytest.fixture
def running_execution(session):
    execution = AgentExecutionFactory.create(running=True, successful=None, end_date=None)
    session.commit()
    return execution


def report_status(dispatcher, execution, **status):
    dispatcher.on_run_status(json.dumps({'execution_ids': [execution.id], **status}))


def reload(session, execution):
    session.expire_all()
    return session.get(AgentExecution, execution.id)


class TestRunStatusEndDate:

    @pytest.mark.parametrize('successful', [True, False])
    def test_end_of_run_sets_end_date(self, session, dispatcher, running_execution, successful):
        report_status(dispatcher, running_execution, running=False, successful=successful)

        assert reload(session, running_execution).end_date is not None

    def test_still_running_does_not_set_end_date(self, session, dispatcher, running_execution):
        report_status(dispatcher, running_execution, running=True, message='half way')

        assert reload(session, running_execution).end_date is None

    def test_repeated_end_report_keeps_the_first_end_date(self, session, dispatcher, running_execution):
        report_status(dispatcher, running_execution, running=False, successful=True)
        first_end_date = reload(session, running_execution).end_date

        report_status(dispatcher, running_execution, running=False, successful=True)

        assert reload(session, running_execution).end_date == first_end_date

    def test_agent_disconnection_sets_end_date(self, app, session, test_client, workspace):
        agent = AgentFactory.create(token='end-date-agent')
        executor = ExecutorFactory.create(agent=agent)
        execution = AgentExecutionFactory.create(executor=executor, running=True, successful=None, end_date=None)
        session.commit()
        token = test_client.post('/v3/agent_websocket_token',
                                 headers={"Authorization": f"Agent {agent.token}"}).json['token']
        client = socketio.test_client(app, namespace='/dispatcher')
        # Joining with the agent's executor, otherwise it's deleted along with its executions
        client.emit("join_agent", {"workspace": workspace.name, "token": token,
                                   "executors": [{"executor_name": executor.name, "args": {}}]},
                    namespace='/dispatcher')

        client.disconnect(namespace='/dispatcher')

        assert reload(session, execution).end_date is not None


@pytest.mark.usefixtures('logged_user')
class TestAgentExecutionsEndDateApi:

    def test_end_date_is_dumped(self, test_client, session):
        execution = AgentExecutionFactory.create(running=False, successful=True,
                                                 end_date=datetime.datetime(2030, 1, 1, 12, 30))
        session.commit()

        res = test_client.get(f'/v3/agent_executions/{execution.id}')

        assert res.json['end_date'] == '2030-01-01T12:30:00+00:00'

    def test_filter_by_end_date_range(self, test_client, session):
        inside = AgentExecutionFactory.create(running=False, end_date=datetime.datetime(2030, 1, 15))
        outside = AgentExecutionFactory.create(running=False, end_date=datetime.datetime(2030, 3, 1))
        session.commit()
        filters = [{"name": "end_date", "op": ">=", "val": "2030-01-01"},
                   {"name": "end_date", "op": "<=", "val": "2030-01-31"}]

        res = test_client.get(f'/v3/agent_executions/filter?q={json.dumps({"filters": filters})}')

        ids = {row['id'] for row in res.json['rows']}
        assert inside.id in ids
        assert outside.id not in ids
