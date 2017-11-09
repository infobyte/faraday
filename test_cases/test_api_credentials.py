import pytest

from test_cases import factories
from test_api_workspaced_base import (
    ReadOnlyAPITests,
)
from server.api.modules.credentials import CredentialView
from server.models import Credential
from test_cases.factories import HostFactory, ServiceFactory


class TestCredentialsAPIGeneric(ReadOnlyAPITests):
    model = Credential
    factory = factories.CredentialFactory
    view_class = CredentialView
    api_endpoint = 'credential'
    update_fields = ['username', 'password']

    @pytest.mark.usefixtures('ignore_nplusone')
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
            "parent": host.id,
            "parent_type": "Host"
        }
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201

    def test_get_credentials_for_a_host_backwards_compatibility(self, session, test_client):
        credential = self.factory.create()
        session.commit()
        res = test_client.get(self.url(workspace=credential.workspace) + '?host_id={0}'.format(credential.host.id))
        assert res.status_code == 200
        assert map(lambda cred: cred['value']['parent'],res.json['rows']) == [credential.host.id]
        assert map(lambda cred: cred['value']['parent_type'], res.json['rows']) == [u'Host']

    def test_get_credentials_for_a_service_backwards_compatibility(self, session, test_client):
        service = ServiceFactory.create()
        credential = self.factory.create(service=service, host=None, workspace=service.workspace)
        session.commit()
        res = test_client.get(self.url(workspace=credential.workspace) + '?service={0}'.format(credential.service.id))
        assert res.status_code == 200
        assert map(lambda cred: cred['value']['parent'],res.json['rows']) == [credential.service.id]
        assert map(lambda cred: cred['value']['parent_type'], res.json['rows']) == [u'Service']

    def _generate_raw_update_data(self, name, username, password, parent_id):
        return {
            "id": 7,
            "name": name,
            "username": username,
            "metadata": {"update_time": 1508960699994, "create_time": 1508965372,
                         "update_user": "", "update_action": 0, "creator": "Metasploit", "owner": "",
                         "update_controller_action": "No model controller call",
                         "command_id": "e1a042dd0e054c1495e1c01ced856438"},
            "password": password,
            "type": "Cred",
            "parent_type": "Host",
            "parent": parent_id,
            "owner": "",
            "description": "",
            "_rev": ""}

    def test_update_credentials_with_invalid_parent(self, test_client, session):
        credential = self.factory.create()
        session.commit()

        raw_data = self._generate_raw_update_data('Name1', 'Username2', 'Password3', parent_id=43)

        res = test_client.put(self.url(workspace=credential.workspace) + str(credential.id) + '/', data=raw_data)
        assert res.status_code == 400

    def test_update_credentials(self, test_client, session):
        credential = self.factory.create()
        session.commit()

        raw_data = self._generate_raw_update_data('Name1', 'Username2', 'Password3', parent_id=credential.host.id)

        res = test_client.put(self.url(workspace=credential.workspace) + str(credential.id) + '/', data=raw_data)
        assert res.status_code == 200
        assert res.json['username'] == u'Username2'
        assert res.json['password'] == u'Password3'
        assert res.json['name'] == u'Name1'

    @pytest.mark.parametrize("parent_type, parent_factory", [
        ("Host", HostFactory),
        ("Service", ServiceFactory),
    ], ids=["with host parent", "with service parent"])
    def test_create_with_parent_of_other_workspace(
            self, parent_type, parent_factory, test_client, session,
            second_workspace):
        parent = parent_factory.create(workspace=second_workspace)
        session.commit()
        assert parent.workspace_id != self.workspace.id
        data = {
            "username": "admin",
            "password": "admin",
            "name": "test",
            "parent_type": parent_type,
            "parent": parent.id
        }
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 400
        assert 'Parent id not found' in res.data

    @pytest.mark.parametrize("parent_type, parent_factory", [
        ("Host", HostFactory),
        ("Service", ServiceFactory),
    ], ids=["with host parent", "with service parent"])
    def test_update_with_parent_of_other_workspace(
            self, parent_type, parent_factory, test_client, session,
            second_workspace, credential_factory):
        parent = parent_factory.create(workspace=second_workspace)
        if parent_type == 'Host':
            credential = credential_factory.create(
                host=HostFactory.create(workspace=self.workspace),
                service=None,
                workspace=self.workspace)
        else:
            credential = credential_factory.create(
                host=None,
                service=ServiceFactory.create(workspace=self.workspace),
                workspace=self.workspace)
        session.commit()
        assert parent.workspace_id != self.workspace.id
        data = {
            "username": "admin",
            "password": "admin",
            "name": "test",
            "parent_type": parent_type,
            "parent": parent.id
        }
        res = test_client.put(self.url(credential), data=data)
        assert res.status_code == 400
        assert 'Parent id not found' in res.data
