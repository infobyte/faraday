'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import base64

import pytest
from tests import factories
from flask_security.utils import hash_password
from faraday.server.api.modules.websocket_auth import decode_agent_websocket_token


class TestWebsocketAuthEndpoint:
    def test_not_logged_in_request_fail(self, test_client, workspace):
        res = test_client.post(f'/v3/ws/{workspace.name}/websocket_token')
        assert res.status_code == 401

    @pytest.mark.usefixtures('logged_user')
    def test_get_method_succeeds(self, test_client, workspace):
        res = test_client.get(f'/v3/ws/{workspace.name}/websocket_token')
        assert res.status_code == 200

        # A token for that workspace should be generated,
        # This will break if we change the token generation
        # mechanism.
        assert res.json['token'].startswith(str(workspace.id))

    @pytest.mark.usefixtures('logged_user')
    def test_post_method_succeeds(self, test_client, workspace):
        res = test_client.post(f'/v3/ws/{workspace.name}/websocket_token')
        assert res.status_code == 200

        # A token for that workspace should be generated,
        # This will break if we change the token generation
        # mechanism.
        assert res.json['token'].startswith(str(workspace.id))


class TestAgentWebsocketToken:

    @pytest.mark.usefixtures('session')  # I don't know why this is required
    def test_fails_without_authorization_header(self, test_client):
        res = test_client.post('/v3/agent_websocket_token')

        assert res.status_code == 401

    @pytest.mark.usefixtures('logged_user')
    def test_fails_with_logged_user(self, test_client):
        res = test_client.post(
            '/v3/agent_websocket_token'
        )
        assert res.status_code == 401

    @pytest.mark.usefixtures('logged_user')
    def test_fails_with_user_token(self, test_client, session):
        res = test_client.get('/v3/token')

        assert res.status_code == 200

        headers = [('Authorization', 'Token ' + res.json)]

        # clean cookies make sure test_client has no session
        test_client.cookie_jar.clear()
        res = test_client.post(
            '/v3/agent_websocket_token',
            headers=headers,
        )
        assert res.status_code == 401

    @pytest.mark.usefixtures('session')
    def test_fails_with_invalid_agent_token(self, test_client):
        headers = [('Authorization', 'Agent 13123')]
        res = test_client.post(
            '/v3/agent_websocket_token',
            headers=headers,
        )
        assert res.status_code == 403

    @pytest.mark.usefixtures('session')
    def test_succeeds_with_agent_token(self, test_client, agent, session):
        session.add(agent)
        session.commit()
        assert agent.token
        headers = [('Authorization', 'Agent ' + agent.token)]
        res = test_client.post(
            '/v3/agent_websocket_token',
            headers=headers,
        )
        assert res.status_code == 200
        decoded_agent = decode_agent_websocket_token(res.json['token'])
        assert decoded_agent == agent


class TestBasicAuth:

    def test_basic_auth_invalid_credentials(self, test_client, session):
        """
            Use of invalid Basic Auth credentials
        """

        alice = factories.UserFactory.create(
                active=True,
                username='asdasd',
                password=hash_password('asdasd'),
                roles=['admin'])
        session.add(alice)
        session.commit()

        agent = factories.AgentFactory.create()
        session.add(agent)
        session.commit()

        valid_credentials = base64.b64encode(b"asdasd:wrong_password").decode("utf-8")
        headers = [('Authorization', f'Basic {valid_credentials}')]
        res = test_client.get('/v3/agents', headers=headers)
        assert res.status_code == 401

    def test_basic_auth_valid_credentials(self, test_client, session):
        """
            Use of valid Basic Auth credentials
        """

        alice = factories.UserFactory.create(
                active=True,
                username='asdasd',
                password=hash_password('asdasd'),
                roles=['admin'])
        session.add(alice)
        session.commit()

        agent = factories.AgentFactory.create()
        session.add(agent)
        session.commit()

        valid_credentials = base64.b64encode(b"asdasd:asdasd").decode("utf-8")
        headers = [('Authorization', f'Basic {valid_credentials}')]
        res = test_client.get('/v3/agents', headers=headers)
        assert res.status_code == 200
