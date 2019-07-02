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
class TestAgentAuthTokenAPIGeneric(ReadOnlyAPITests):
    model = AgentAuthToken
    factory = factories.AgentAuthTokenFactory
    view_class = AgentAuthTokenView
    api_endpoint = 'agent_tokens'

    def create_raw_agent_token(self, token="D3FaULT0k3N"):
        return {
            "token": token
        }

    def test_multiple_post_return_the_same_id(self, session, test_client):
        session.query(AgentAuthToken).delete()
        initial_agent_token_count = session.query(AgentAuthToken).count()
        raw_agent = self.create_raw_agent_token()
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 201
        assert len(session.query(AgentAuthToken).all()) == initial_agent_token_count + 1
        initial_agent_token_count = session.query(AgentAuthToken).count()
        raw_agent = self.create_raw_agent_token(token="pepito")
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 201
        # the second post will not create more entries
        assert session.query(AgentAuthToken).count() == initial_agent_token_count

    def test_create_agent_token(self, test_client, session):
        session.query(AgentAuthToken).delete()
        initial_agent_token_count = session.query(AgentAuthToken).count()
        raw_agent = self.create_raw_agent_token()
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 201
        assert session.query(AgentAuthToken).count() == initial_agent_token_count + 1

    def test_delete_agent_token(self, test_client, session):
        session.query(AgentAuthToken).delete()
        initial_agent_token_count = session.query(AgentAuthToken).count()
        agent_token = AgentAuthTokenFactory.create()
        session.commit()
        assert session.query(AgentAuthToken).count() == initial_agent_token_count + 1
        res = test_client.delete(self.url(agent_token.id))
        assert res.status_code == 204
        assert session.query(AgentAuthToken).count() == initial_agent_token_count
