import json

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
        session.expire_all()
        agent = Agent.query.one()
        assert agent.is_online

        client.emit("leave_agent", namespace='/dispatcher')
        assert client.is_connected() is False
        session.expire_all()
        agent = Agent.query.one()
        assert not agent.is_online


def join_agent(app, test_client, session, workspace, **extra):
    agent = AgentFactory.create(token='pepito')
    session.add(agent)
    session.commit()
    headers = {"Authorization": f"Agent {agent.token}"}
    token = test_client.post('/v3/agent_websocket_token', headers=headers).json['token']
    client = socketio.test_client(app, namespace='/dispatcher')
    message = {"action": "JOIN_AGENT", "workspace": workspace.name, "token": token, "executors": [], **extra}
    client.emit("join_agent", message, namespace='/dispatcher')
    session.expire_all()
    return client, Agent.query.one()


class TestAgentFeatures:
    join = staticmethod(join_agent)

    def test_features_are_stored_on_join(self, app, test_client, session, workspace):
        _, agent = self.join(app, test_client, session, workspace, features=['remote_config'])

        assert agent.features == ['remote_config']
        assert agent.remote_config is True

    def test_agent_without_features_has_no_remote_config(self, app, test_client, session, workspace):
        _, agent = self.join(app, test_client, session, workspace)

        assert agent.features == []
        assert agent.remote_config is False

    def test_features_are_replaced_on_rejoin(self, app, test_client, session, workspace):
        client, agent = self.join(app, test_client, session, workspace, features=['remote_config'])
        token = test_client.post('/v3/agent_websocket_token',
                                 headers={"Authorization": f"Agent {agent.token}"}).json['token']

        client.emit("join_agent", {"token": token, "executors": []}, namespace='/dispatcher')
        session.expire_all()

        assert Agent.query.one().remote_config is False

    def test_invalid_features_are_ignored(self, app, test_client, session, workspace):
        _, agent = self.join(app, test_client, session, workspace, features='remote_config')

        assert agent.features == []
        assert agent.is_online


class TestAgentCapabilities:
    PAYLOAD = {
        "version": 1,
        "executors": [{"repo_name": "nmap", "available": True}, {"repo_name": "burp", "available": False}],
        "manifests_digest": "abc123",
        "manifests_count": 177,
    }

    def announce(self, client, session, payload):
        client.emit("agent_capabilities", payload, namespace='/dispatcher')
        session.expire_all()
        return Agent.query.one()

    def test_capabilities_are_stored(self, app, test_client, session, workspace):
        client, _ = join_agent(app, test_client, session, workspace)

        agent = self.announce(client, session, self.PAYLOAD)

        assert agent.capabilities == self.PAYLOAD["executors"]
        assert agent.manifests_digest == "abc123"

    def test_capabilities_are_replaced_on_a_new_announcement(self, app, test_client, session, workspace):
        client, _ = join_agent(app, test_client, session, workspace)
        self.announce(client, session, self.PAYLOAD)

        agent = self.announce(client, session, {**self.PAYLOAD, "executors": [{"repo_name": "zap", "available": True}],
                                                "manifests_digest": "def456"})

        assert agent.capabilities == [{"repo_name": "zap", "available": True}]
        assert agent.manifests_digest == "def456"

    def test_json_string_payload_is_accepted(self, app, test_client, session, workspace):
        client, _ = join_agent(app, test_client, session, workspace)

        agent = self.announce(client, session, json.dumps(self.PAYLOAD))

        assert agent.capabilities == self.PAYLOAD["executors"]

    def test_invalid_entries_are_dropped(self, app, test_client, session, workspace):
        client, _ = join_agent(app, test_client, session, workspace)
        executors = [{"repo_name": "nmap", "available": True}, {"available": True}, {"repo_name": "zap"},
                     {"repo_name": 3, "available": True}, "burp", {"repo_name": "burp", "available": "yes"}]

        agent = self.announce(client, session, {**self.PAYLOAD, "executors": executors})

        assert agent.capabilities == [{"repo_name": "nmap", "available": True}]

    def test_malformed_payload_keeps_what_was_stored(self, app, test_client, session, workspace):
        client, _ = join_agent(app, test_client, session, workspace)
        self.announce(client, session, self.PAYLOAD)

        agent = self.announce(client, session, {"executors": "nmap"})

        assert agent.capabilities == self.PAYLOAD["executors"]

    def test_announcement_from_an_unknown_sid_is_ignored(self, app, session):
        agent = AgentFactory.create(sid=None)
        session.commit()
        client = socketio.test_client(app, namespace='/dispatcher')

        client.emit("agent_capabilities", self.PAYLOAD, namespace='/dispatcher')
        session.expire_all()

        assert Agent.query.get(agent.id).capabilities == []


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

    def test_new_executor_is_enabled_by_default(self, session):
        agent = AgentFactory.create()
        executors = [
            {'executor_name': 'executor 1', 'args': {}}
        ]

        assert update_executors(agent, executors)
        executor = Executor.query.filter_by(agent=agent).one()
        assert executor.enabled is True
        assert executor.varenvs_set == []

    def test_enabled_and_varenvs_set_are_read_from_announcement(self, session):
        agent = AgentFactory.create()
        executors = [
            {'executor_name': 'executor 1', 'args': {}, 'enabled': False, 'varenvs_set': ['API_KEY']}
        ]

        assert update_executors(agent, executors)
        executor = Executor.query.filter_by(agent=agent).one()
        assert executor.enabled is False
        assert executor.varenvs_set == ['API_KEY']

    def test_executor_can_be_enabled_again(self, session):
        agent = AgentFactory.create()
        ExecutorFactory.create(name='executor 1', agent=agent, enabled=False, varenvs_set=['API_KEY'])
        session.commit()
        executors = [
            {'executor_name': 'executor 1', 'args': {}, 'enabled': True, 'varenvs_set': []}
        ]

        assert update_executors(agent, executors)
        executor = Executor.query.filter_by(agent=agent).one()
        assert executor.enabled is True
        assert executor.varenvs_set == []

    def test_announcement_without_enabled_keeps_current_value(self, session):
        # Dispatchers without remote_config do not send these fields
        agent = AgentFactory.create()
        ExecutorFactory.create(name='executor 1', agent=agent, enabled=False)
        session.commit()
        executors = [
            {'executor_name': 'executor 1', 'args': {}}
        ]

        assert update_executors(agent, executors)
        executor = Executor.query.filter_by(agent=agent).one()
        assert executor.enabled is False

    def test_disabled_executor_is_not_deleted_when_announced(self, session):
        agent = AgentFactory.create()
        executors = [
            {'executor_name': 'executor 1', 'args': {}, 'enabled': False}
        ]

        assert update_executors(agent, executors)
        assert update_executors(agent, executors)
        assert Executor.query.filter_by(agent=agent).count() == 1
