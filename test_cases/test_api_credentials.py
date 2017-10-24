from test_cases import factories
from test_api_workspaced_base import (
    ReadOnlyAPITests,
)
from server.api.modules.credentials import CredentialView
from server.models import Credential


class TestCredentialsAPIGeneric(ReadOnlyAPITests):
    model = Credential
    factory = factories.CredentialFactory
    view_class = CredentialView
    api_endpoint = 'credential'
    update_fields = ['username', 'password']

    def test_get_list_backwards_compatibility(self, test_client, session, second_workspace):
        cred = self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'rows' in res.json
        for vuln in res.json['rows']:
            assert set([u'id', u'key', u'value']) == set(vuln.keys())
            object_properties = [
                u'_id',
                u'couchdbid',
                u'description',
                u'metadata',
                u'name',
                u'owned',
                u'owner',
                u'password',
                u'username',
            ]
            expected = set(object_properties)
            result = set(vuln['value'].keys())
            assert expected - result == set()

    def test_create_from_raw_data_host_as_parent(self, session, test_client,
                                  workspace, host_factory):
        host = host_factory.create(workspace=workspace)
        session.commit()
        raw_data = {
            "_id":"1.e5069bb0718aa519852e6449448eedd717f1b90d",
            "name":"name",
            "username":"username",
            "metadata":{"update_time":1508794240799,"update_user":"",
                        "update_action":0,"creator":"UI Web",
                        "create_time":1508794240799,"update_controller_action":"",
                        "owner":""},
            "password":"pass",
            "type":"Cred",
            "owner":"",
            "description":"",
            "parent_id": host.id,
            "parent_type": "Host"
        }
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
