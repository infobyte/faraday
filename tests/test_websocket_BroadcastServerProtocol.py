import pytest
from faraday.server.websocket_factories import WorkspaceServerFactory

from tests.factories import AgentFactory

def _join_agent(test_client, session):
    agent = AgentFactory.create(token='pepito')
    session.add(agent)
    session.commit()

    headers = {"Authorization": "Agent {}".format(agent.token)}
    token = test_client.post('v2/agent_websocket_token/', headers=headers).json['token']
    return token


@pytest.fixture
def proto():
    factory = WorkspaceServerFactory('ws://127.0.0.1')
    proto = factory.buildProtocol(('127.0.0.1', 0))
    return proto


class TestWebsockerBroadcastServerProtocol():

    def test_join_agent_message_with_invalid_token_fails(self, session, proto, test_client):
        message = '{"action": "JOIN_AGENT", "token": "pepito" }'
        assert not proto.onMessage(message, False)

    def test_join_agent_message_without_token_fails(self, session, proto, test_client):
        message = '{"action": "JOIN_AGENT"}'
        assert not proto.onMessage(message, False)

    def test_join_agent_message_with_valid_token(self, session, proto, test_client):
        token = _join_agent(test_client, session)
        message = '{{"action": "JOIN_AGENT", "token": "{}" }}'.format(token)
        assert proto.onMessage(message, False)

    def test_leave_agent_happy_path(self, session, proto, test_client):
        token = _join_agent(test_client, session)
        message = '{{"action": "JOIN_AGENT", "token": "{}" }}'.format(token)
        assert proto.onMessage(message, False)

        message = '{{"action": "LEAVE_AGENT", "token": "{}" }}'.format(token)
        assert proto.onMessage(message, False)

    def test_leave_agent_without_token_fails(self, session, proto, test_client):
        token = _join_agent(test_client, session)
        message = '{{"action": "JOIN_AGENT", "token": "{}" }}'.format(token)
        assert proto.onMessage(message, False)

        message = '{{"action": "LEAVE_AGENT" }}'.format(token)
        assert not proto.onMessage(message, False)

    def test_leave_agent_with_invalid_token_fails(self, session, proto, test_client):
        token = _join_agent(test_client, session)
        message = '{{"action": "JOIN_AGENT", "token": "{}" }}'.format(token)
        assert proto.onMessage(message, False)

        message = '{{"action": "LEAVE_AGENT", "token": "pepito" }}'.format(token)
        assert not proto.onMessage(message, False)

