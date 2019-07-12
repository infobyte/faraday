"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import mock
import pytest


@pytest.mark.usefixtures('logged_user')
class TestAgentAuthTokenAPIGeneric():

    @mock.patch('faraday.server.api.modules.agent.faraday_server')
    def test_create_agent_token(self, faraday_server_config, test_client, session):
        faraday_server_config.agent_token = None
        res = test_client.get('/v2/agent_token/')
        assert 'token' in res.json
        assert len(res.json['token']) == 20
