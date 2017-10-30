#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest
from test_cases import factories
from test_api_non_workspaced_base import ReadWriteAPITests, API_PREFIX
from server.models import (
    License,
    Workspace,
)
from server.api.modules.licenses import LicenseView
from server.api.modules.workspaces import WorkspaceView

class LicenseEnvelopedView(LicenseView):
    """A custom view to test that enveloping on generic views work ok"""
    route_base = "test_envelope_list"

    def _envelope_list(self, objects, pagination_metadata=None):
        return {"object_list": objects}


class TestLicensesAPI(ReadWriteAPITests):
    model = License
    factory = factories.LicenseFactory
    api_endpoint = 'licenses'
    # unique_fields = ['ip']
    # update_fields = ['ip', 'description', 'os']

    def test_envelope_list(self, test_client, app):
        LicenseEnvelopedView.register(app)
        original_res = test_client.get(self.url())
        assert original_res.status_code == 200
        new_res = test_client.get(API_PREFIX + 'test_envelope_list/')
        assert new_res.status_code == 200

        assert new_res.json == {"object_list": original_res.json}


class TestWorkspaceAPI(ReadWriteAPITests):
    model = Workspace
    factory = factories.WorkspaceFactory
    api_endpoint = 'ws'
    lookup_field = 'name'

    def test_host_count(self, host_factory, test_client, session):
        host_factory.create(workspace=self.first_object)
        session.commit()
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        assert res.json['stats']['hosts'] == 1

    @pytest.mark.parametrize('querystring', [
        '',
        '?confirmed=0',
        '?confirmed=false'
    ])
    def test_vuln_count(self, vulnerability_factory, test_client, session,
                        querystring):
        vulnerability_factory.create_batch(8, workspace=self.first_object,
                                           confirmed=False)
        vulnerability_factory.create_batch(5, workspace=self.first_object,
                                           confirmed=True)
        session.commit()
        res = test_client.get(self.url(self.first_object) + querystring)
        assert res.status_code == 200
        assert res.json['stats']['total_vulns'] == 13

    @pytest.mark.parametrize('querystring', [
        '?confirmed=1',
        '?confirmed=true'
    ])
    def test_vuln_count_confirmed(self, vulnerability_factory, test_client,
                                  session, querystring):
        vulnerability_factory.create_batch(8, workspace=self.first_object,
                                           confirmed=False)
        vulnerability_factory.create_batch(5, workspace=self.first_object,
                                           confirmed=True)
        session.commit()
        res = test_client.get(self.url(self.first_object) + querystring)
        assert res.status_code == 200
        assert res.json['stats']['total_vulns'] == 5
