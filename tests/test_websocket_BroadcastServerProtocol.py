
import pytest
from faraday.server.models import Agent, Executor
from faraday.server.websocket_factories import WorkspaceServerFactory, \
    update_executors, BroadcastServerProtocol

from tests.factories import AgentFactory, ExecutorFactory


def _join_agent(test_client, session):
    agent = AgentFactory.create(token='pepito')
    session.add(agent)
    session.commit()

    headers = {"Authorization": f"Agent {agent.token}"}
    token = test_client.post('v2/agent_websocket_token/', headers=headers).json['token']
    return token


class TransportMock:
    def write(self, data: bytearray):
        pass


@pytest.fixture
def proto():
    factory = WorkspaceServerFactory('ws://127.0.0.1')
    proto = factory.buildProtocol(('127.0.0.1', 0))
    proto.maskServerFrames = False
    proto.logFrames = False
    proto.send_queue = []
    proto.state = BroadcastServerProtocol.STATE_CLOSING
    proto.transport = TransportMock()

    return proto


class TestWebsocketBroadcastServerProtocol:

    def test_join_agent_message_with_invalid_token_fails(self, session, proto, test_client):
        message = '{"action": "JOIN_AGENT", "token": "pepito" }'
        assert not proto.onMessage(message, False)

    def test_join_agent_message_without_token_fails(self, session, proto, test_client):
        message = '{"action": "JOIN_AGENT"}'
        assert not proto.onMessage(message, False)

    def test_join_agent_message_with_valid_token(self, session, proto, workspace, test_client):
        token = _join_agent(test_client, session)
        message = f'{{"action": "JOIN_AGENT", "workspace": "{workspace.name}", "token": "{token}", "executors": [] }}'
        assert proto.onMessage(message, False)

    def test_leave_agent_happy_path(self, session, proto, workspace, test_client):
        token = _join_agent(test_client, session)
        message = f'{{"action": "JOIN_AGENT", "workspace": "{workspace.name}", "token": "{token}", "executors": [] }}'
        assert proto.onMessage(message, False)

        message = '{"action": "LEAVE_AGENT" }'
        assert proto.onMessage(message, False)

    def test_agent_status(self, session, proto, workspace, test_client):
        token = _join_agent(test_client, session)
        agent = Agent.query.one()
        assert not agent.is_online
        message = f'{{"action": "JOIN_AGENT", "workspace": "{workspace.name}", "token": "{token}", "executors": [] }}'
        assert proto.onMessage(message, False)
        assert agent.is_online

        message = '{"action": "LEAVE_AGENT"}'
        assert proto.onMessage(message, False)
        assert not agent.is_online


class TestCheckExecutors:

    def test_new_executors_not_in_database(self, session):
        agent = AgentFactory.create()
        executors = [
            {'executor_name': 'nmap_executor', 'args': {'param1': True}}
        ]

        assert update_executors(agent, executors)

    def test_executors_with_missing_args(self, session):
        agent = AgentFactory.create()
        executors = [
            {'executor_name': 'nmap_executor'}
        ]

        assert update_executors(agent, executors)

    def test_executors_with_missing_executor_name(self, session):
        agent = AgentFactory.create()
        executors = [
            {'invalid_key': 'nmap_executor'}
        ]

        assert update_executors(agent, executors)

    def test_executors_with_some_invalid_executors(self, session):
        agent = AgentFactory.create()
        executors = [
            {'invalid_key': 'nmap_executor'},
            {'executor_name': 'executor 1', 'args': {'param1': True}}
        ]

        assert update_executors(agent, executors)
        count_executors = Executor.query.filter_by(agent=agent).count()
        assert count_executors == 1

    def test_executor_already_in_database_but_new_parameters_incoming(self, session):
        agent = AgentFactory.create()
        old_params = {'old_param': True}
        executor = ExecutorFactory.create(agent=agent, parameters_metadata=old_params)
        session.add(executor)
        session.commit()
        new_params = old_params
        new_params.update({'param1': True})
        executors = [
            {'executor_name': executor.name, 'args': new_params}
        ]

        assert update_executors(agent, executors)
        from_db_executor = Executor.query.filter_by(id=executor.id, agent=agent).first()
        assert from_db_executor.parameters_metadata == new_params

    def test_new_executor_and_delete_the_old_one(self, session):
        agent = AgentFactory.create()
        params = {'old_param': True}
        executor = ExecutorFactory.create(
            name='old_executor',
            agent=agent,
            parameters_metadata=params
        )
        session.add(executor)
        session.commit()
        executors = [
            {'executor_name': 'new executor', 'args': {'param1': True}}
        ]

        assert update_executors(agent, executors)
        count_executors = Executor.query.filter_by(agent=agent).count()
        assert count_executors == 1
        current_executor = Executor.query.filter_by(agent=agent).first()
        assert current_executor.name == 'new executor'
        assert current_executor.parameters_metadata == {'param1': True}

    def test_remove_all_executors(self, session):
        agent = AgentFactory.create()
        params = {'old_param': True}
        executor = ExecutorFactory.create(
            name='old_executor',
            agent=agent,
            parameters_metadata=params
        )
        session.add(executor)
        session.commit()
        executors = [
        ]

        assert update_executors(agent, executors)
        count_executors = Executor.query.filter_by(agent=agent).count()
        assert count_executors == 0

    def test_remove_one_of_two_executors(self, session):
        agent = AgentFactory.create()
        executor = ExecutorFactory.create(
            name='executor 1',
            agent=agent,
            parameters_metadata={'param1': True}
        )
        session.add(executor)
        another_executor = ExecutorFactory.create(
            name='executor 2',
            agent=agent,
            parameters_metadata={'param2': True}
        )
        session.add(executor)
        session.add(another_executor)
        session.commit()
        executors = [
            {'executor_name': 'executor 2', 'args': {'param2': True}}
        ]

        assert update_executors(agent, executors)
        count_executors = Executor.query.filter_by(agent=agent).count()
        assert count_executors == 1
        from_db_executor = Executor.query.filter_by(id=another_executor.id, agent=agent).first()
        assert from_db_executor.name == 'executor 2'
