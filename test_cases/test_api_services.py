#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest

from server.api.modules.vulns import VulnerabilityView
from test_cases import factories
from test_api_workspaced_base import ListTestsMixin, API_PREFIX, GenericAPITest
from server.models import (
    Service
)
from server.api.modules.commandsrun import CommandView
from server.api.modules.workspaces import WorkspaceView


@pytest.mark.usefixtures('logged_user')
class TestListServiceView(GenericAPITest):
    model = Service
    factory = factories.ServiceFactory
    api_endpoint = 'services'
    #unique_fields = ['ip']
    #update_fields = ['ip', 'description', 'os']
    view_class = VulnerabilityView

    def test_(self, test_client, second_workspace, session):
        self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'services' in res.json
        for vuln in res.json['services']:
            assert set([u'id', u'key', u'value']) == set(vuln.keys())
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
                u'ports',
                u'metadata'
            ]
            expected = set(object_properties)
            result = set(vuln['value'].keys())
            assert expected <= result
