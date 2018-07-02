'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import pytest


class TestWebsocketAuthEndpoint:

    def test_not_logged_in_request_fail(self, test_client, workspace):
        res = test_client.post('/v2/ws/{}/websocket_token/'.format(
            workspace.name))
        assert res.status_code == 401

    @pytest.mark.usefixtures('logged_user')
    def test_get_method_not_allowed(self, test_client, workspace):
        res = test_client.get('/v2/ws/{}/websocket_token/'.format(
            workspace.name))
        assert res.status_code == 405

    @pytest.mark.usefixtures('logged_user')
    def test_succeeds(self, test_client, workspace):
        res = test_client.post('/v2/ws/{}/websocket_token/'.format(
            workspace.name))
        assert res.status_code == 200

        # A token for that workspace should be generated,
        # This will break if we change the token generation
        # mechanism.
        assert res.json['token'].startswith(str(workspace.id))
