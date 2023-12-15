from faraday.server.models import Executor, Agent
from faraday.server.extensions import socketio
from faraday.server.websockets.dispatcher import update_executors
from tests.factories import AgentFactory, ExecutorFactory


class TestSockets:
    def join_agent(self, test_client, session):
        agent = AgentFactory.create(token='pepito')
        session.add(agent)
        session.commit()

        headers = {"Authorization": f"Agent {agent.token}"}
        token = test_client.post('/v3/agent_websocket_token', headers=headers).json['token']
        return token  # TODO: return agent too.

    def test_connect_namespace(self, app, session):
        client = socketio.test_client(app, namespace='/dispatcher')
        assert client.is_connected('/dispatcher') is True

    def test_join_agent(self, app, test_client, session, workspace):
        token = self.join_agent(test_client, session)
        assert token is not None

        client = socketio.test_client(app, namespace='/dispatcher')
        assert client.is_connected('/dispatcher') is True

        message = {
            "action": "JOIN_AGENT",
            "workspace": workspace.name,
            "token": token,
            "executors": []
        }
        client.emit("join_agent", message, namespace='/dispatcher')
        received = client.get_received(namespace='/dispatcher')
        assert received[-1]['args'] == 'Agent joined correctly to dispatcher namespace'

    def test_join_agent_message_with_invalid_token_fails(self, app, session):
        client = socketio.test_client(app, namespace='/dispatcher')
        assert client.is_connected('/dispatcher') is True

        message = {"action": "JOIN_AGENT", "token": "pepito"}
        client.emit("join_agent", message, namespace='/dispatcher')
        received = client.get_received(namespace='/dispatcher')
        assert received[-1]['args'][0]['reason'] == 'Invalid join agent message'

    def test_join_agent_message_without_token_fails(self, app, session):
        client = socketio.test_client(app, namespace='/dispatcher')
        assert client.is_connected('/dispatcher') is True

        message = {"action": "JOIN_AGENT"}
        client.emit("join_agent", message, namespace='/dispatcher')
        received = client.get_received(namespace='/dispatcher')
        assert received[-1]['args'][0]['reason'] == 'Invalid join agent message'

    def test_leave_agent_happy_path(self, app, session, workspace, test_client):
        token = self.join_agent(test_client, session)
        assert token is not None

        client = socketio.test_client(app, namespace='/dispatcher')
        assert client.is_connected('/dispatcher') is True

        message = {
            "action": "JOIN_AGENT",
            "workspace": workspace.name,
            "token": token,
            "executors": []
        }
        client.emit("join_agent", message, namespace='/dispatcher')

        received = client.get_received(namespace='/dispatcher')
        assert received[-1]['args'] == 'Agent joined correctly to dispatcher namespace'

        client.emit("leave_agent", namespace='/dispatcher')
        assert client.is_connected() is False

    def test_agent_status(self, app, session, workspace, test_client):
        token = self.join_agent(test_client, session)
        assert token is not None
        agent = Agent.query.one()
        assert not agent.is_online

        client = socketio.test_client(app, namespace='/dispatcher')
        assert client.is_connected('/dispatcher') is True

        message = {
            "action": "JOIN_AGENT",
            "workspace": workspace.name,
            "token": token,
            "executors": []
        }
        client.emit("join_agent", message, namespace='/dispatcher')
        agent = Agent.query.one()
        assert agent.is_online

        client.emit("leave_agent", namespace='/dispatcher')
        assert client.is_connected() is False
        agent = Agent.query.one()
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
