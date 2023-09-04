'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""Tests for many API endpoints that do not depend on workspace_name"""
import pytest

from faraday.server.api.modules.services import ServiceView
from tests import factories
from tests.test_api_non_workspaced_base import ReadOnlyAPITests, BulkDeleteTestsMixin, BulkUpdateTestsMixin, OBJECT_COUNT
from faraday.server.models import (
    Service
)
from tests.factories import CredentialFactory, VulnerabilityFactory


@pytest.mark.usefixtures('logged_user')
class TestListServiceView(ReadOnlyAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin):
    model = Service
    factory = factories.ServiceFactory
    api_endpoint = 'services'
    view_class = ServiceView
    patchable_fields = ['name']

    def control_cant_change_data(self, data: dict):
        if 'parent' in data:
            data['parent'] = self.first_object.host_id
        return data

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_service_list_backwards_compatibility(self, test_client,
                                                  second_workspace, session):
        self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'services' in res.json
        for service in res.json['services']:
            assert {'id', 'key', 'value'} == set(service.keys())
            object_properties = [
                'status',
                'protocol',
                'description',
                '_rev',
                'owned',
                'owner',
                'credentials',
                'name',
                'version',
                '_id',
                'metadata'
            ]
            expected = set(object_properties)
            result = set(service['value'].keys())
            assert expected <= result

    def _raw_put_data(self, id, parent=None, status='open', protocol='tcp', ports=None):
        if not ports:
            ports = [22]
        raw_data = {"status": status,
                    "protocol": protocol,
                    "description": "",
                    "_rev": "",
                    "metadata": {"update_time": 1510945708000, "update_user": "", "update_action": 0, "creator": "",
                                 "create_time": 1510945708000, "update_controller_action": "", "owner": "leonardo",
                                 "command_id": None},
                    "owned": False,
                    "owner": "",
                    "version": "",
                    "_id": id,
                    "ports": ports,
                    "name": "ssh2",
                    "type": "Service"}
        if parent:
            raw_data['parent'] = parent
        return raw_data

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_list_retrieves_all_items_from(self, test_client, logged_user):
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json['services']) == OBJECT_COUNT

    def test_bulk_delete_with_references(self, test_client, session, workspace):
        service_1 = self.factory.create(workspace=workspace)
        service_2 = self.factory.create(workspace=workspace)
        service_3 = self.factory.create(workspace=workspace)

        for _ in range(3):
            CredentialFactory.create(service=service_1, workspace=workspace)
            VulnerabilityFactory.create(service=service_2, workspace=workspace)
            CredentialFactory.create(service=service_3, workspace=workspace)
            VulnerabilityFactory.create(service=service_3, workspace=workspace)
        session.commit()

        raw_data = {'ids': [service_1.id, service_2.id, service_3.id]}
        res = test_client.delete(self.url(), data=raw_data)

        assert res.status_code == 200
        assert res.json['deleted'] == 3
