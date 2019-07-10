"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import pytest

from faraday.server.api.modules.agent_auth_token import AgentAuthTokenView
from faraday.server.models import AgentAuthToken
from tests.factories import AgentAuthTokenFactory
from tests.test_api_non_workspaced_base import ReadOnlyAPITests
from tests import factories


@pytest.mark.usefixtures('logged_user')
class TestAgentAuthTokenAPIGeneric():

    def test_create_agent_token(self, test_client, session):
        assert AgentAuthToken.query.count() == 0
        res = test_client.get('/v2/agent_token/')
        assert 'token' in res.json
        assert AgentAuthToken.query.count() == 1