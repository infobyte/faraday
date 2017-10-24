#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest

from server.api.modules.services import ServiceView
from test_cases import factories
from test_api_workspaced_base import API_PREFIX, ReadOnlyAPITests
from server.models import (
    Service
)
from server.api.modules.commandsrun import CommandView
from server.api.modules.workspaces import WorkspaceView


@pytest.mark.usefixtures('logged_user')
class TestListServiceView(ReadOnlyAPITests):
    model = Service
    factory = factories.ServiceFactory
    api_endpoint = 'services'
    #unique_fields = ['ip']
    #update_fields = ['ip', 'description', 'os']
    view_class = ServiceView

    def test_service_list_backwards_compatibility(self, test_client, second_workspace, session):
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
