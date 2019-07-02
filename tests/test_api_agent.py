"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import pytest

from faraday.server.api.modules.agents import AgentView
from faraday.server.models import Agent, AgentAuthToken
from tests.factories import AgentFactory
from tests.test_api_workspaced_base import ReadOnlyAPITests
from tests import factories


class TestAgentAPIGeneric(ReadOnlyAPITests):
    model = Agent
    factory = factories.AgentFactory
    view_class = AgentView
    api_endpoint = 'agents'

    def create_raw_agent(self, _type='shared', status="offline", token="TOKEN"):
        return {
            "projects": 1,
            "type": _type,
            "version": "1",
            "token": token,
            "status": status,
            "jobs": 1,
            "description": "My Desc"
        }

    def test_create_agent_invalid(self, test_client, session):
        initial_agent_count = len(session.query(Agent).all())
        raw_agent = self.create_raw_agent()
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 401
        assert len(session.query(Agent).all()) == initial_agent_count

    def test_create_agent_valid(self, test_client, session):
        valid_token = 'sarasa_tokenator'
        token_obj = AgentAuthToken(token=valid_token)
        session.add(token_obj)
        session.commit()
        initial_agent_count = len(session.query(Agent).all())
        raw_agent = self.create_raw_agent(token=valid_token)
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 201
        assert len(session.query(Agent).all()) == initial_agent_count + 1

    def test_cannot_create_agent_with_invalid_type(self, test_client):
        raw_agent = self.create_raw_agent(_type="wrong_type")
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 400
        assert res.json == {u'messages': {u'type': [u'Not a valid choice.']}}

    def test_cannot_create_agent_with_invalid_status(self, test_client):
        raw_agent = self.create_raw_agent(status="wrong_status")
        res = test_client.post(self.url(), data=raw_agent)
        assert res.status_code == 400
        assert res.json == {u'messages': {u'status': [u'Not a valid choice.']}}

    def test_update_agent(self, test_client, session):
        agent = AgentFactory.create(workspace=self.workspace, type='shared')
        session.commit()
        raw_agent = self.create_raw_agent(_type="specific")
        res = test_client.put(self.url(agent.id), data=raw_agent)
        assert res.status_code == 200
        assert res.json['type'] == 'specific'

    def test_delete_agent(self, test_client, session):
        initial_agent_count = len(session.query(Agent).all())
        agent = AgentFactory.create(workspace=self.workspace, type='shared')
        session.commit()
        assert len(session.query(Agent).all()) == initial_agent_count + 1
        res = test_client.delete(self.url(agent.id))
        assert res.status_code == 204
        assert len(session.query(Agent).all()) == initial_agent_count
