# -*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest
import json

from server.api.modules.services import ServiceView
from test_cases import factories
from test_api_workspaced_base import ReadOnlyAPITests
from server.models import (
    Service
)


@pytest.mark.usefixtures('logged_user')
class TestListServiceView(ReadOnlyAPITests):
    model = Service
    factory = factories.ServiceFactory
    api_endpoint = 'services'
    #unique_fields = ['ip']
    #update_fields = ['ip', 'description', 'os']
    view_class = ServiceView

    def test_service_list_backwards_compatibility(self, test_client,
                                                  second_workspace, session):
        self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'services' in res.json
        for service in res.json['services']:
            assert set([u'id', u'key', u'value']) == set(service.keys())
            object_properties = [
                u'status',
                u'protocol',
                u'description',
                u'_rev',
                u'owned',
                u'owner',
                u'credentials',
                u'name',
                u'version',
                u'_id',
                u'metadata'
            ]
            expected = set(object_properties)
            result = set(service['value'].keys())
            assert expected <= result

    def test_create_service(self, test_client, host, session):
        session.commit()
        data = {
            "name": "ftp",
            "description": "test. test",
            "owned": False,
            "ports": [21],
            "protocol": "tcp",
            "status": "open",
            "parent": host.id
        }
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 201
        service = Service.query.get(res.json['_id'])
        assert service.name == "ftp"
        assert service.port == 21
        assert service.host is host

    def test_create_fails_with_host_of_other_workspace(self, test_client,
                                                       host, session,
                                                       second_workspace):
        session.commit()
        assert host.workspace_id != second_workspace.id
        data = {
            "name": "ftp",
            "description": "test. test",
            "owned": False,
            "ports": [21],
            "protocol": "tcp",
            "status": "open",
            "parent": host.id
        }
        res = test_client.post(self.url(workspace=second_workspace), data=data)
        assert res.status_code == 400
        assert 'Host with id' in res.data

    def test_update_fails_with_host_of_other_workspace(self, test_client,
                                                       second_workspace,
                                                       host_factory,
                                                       session):
        host = host_factory.create(workspace=second_workspace)
        session.commit()
        assert host.workspace_id != self.first_object.workspace_id
        data = {
            "name": "ftp",
            "description": "test. test",
            "owned": False,
            "ports": [21],
            "protocol": "tcp",
            "status": "open",
            "parent": host.id
        }
        res = test_client.put(self.url(self.first_object), data=data)
        assert res.status_code == 400
        assert 'Host with id' in res.data

    def test_create_service_returns_conflict_if_already_exists(self, test_client, host, session):
        session.commit()
        service = self.first_object
        data = {
            "name": service.name,
            "description": service.description,
            "owned": service.owned,
            "ports": [service.port],
            "protocol": service.protocol,
            "status": service.status,
            "parent": service.host_id
        }
        res = test_client.post(self.url(workspace=service.workspace), data=data)
        assert res.status_code == 409
        message = json.loads(res.data)
        assert message['object']['_id'] == service.id