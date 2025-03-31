import datetime
import io
import pytest
from faraday.server.models import Credential
from faraday.server.api.modules.credentials import CredentialView
from tests.test_api_workspaced_base import ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin
from tests.factories import CredentialFactory, VulnerabilityFactory
from pathlib import Path

"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""


class TestCredentialAPI(ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin):
    model = Credential
    factory = CredentialFactory
    api_endpoint = 'credential'
    view_class = CredentialView
    patchable_fields = ['username', 'password', 'endpoint', 'owned', 'vulnerabilities']
    update_fields = ['username', 'password', 'endpoint', 'owned', 'vulnerabilities']

    def test_list_retrieves_all_items_from_workspace(self, test_client, workspace, session):
        pass

    def test_bulk_update_an_object(self, test_client, logged_user):
        # Results in 409 because of unique constraint
        pass

    def test_create_credential(self, test_client, workspace):
        credential_data = {
            'username': 'testuser',
            'password': 'testpass',
            'endpoint': 'test.example.com',
            'owned': True,
            'workspace': workspace.name
        }
        res = test_client.post(self.url(workspace=workspace), data=credential_data)
        assert res.status_code == 201
        assert res.json['username'] == 'testuser'
        assert res.json['password'] == 'testpass'
        assert res.json['endpoint'] == 'test.example.com'
        assert res.json['owned'] is True

    def test_create_credential_with_leak_date(self, test_client, workspace):
        leak_date = datetime.datetime.now().isoformat()
        credential_data = {
            'username': 'leakeduser',
            'password': 'leakedpass',
            'endpoint': 'leak.example.com',
            'owned': True,
            'leak_date': leak_date,
            'workspace': workspace.name
        }
        res = test_client.post(self.url(workspace=workspace), data=credential_data)
        assert res.status_code == 201
        assert res.json['username'] == 'leakeduser'
        assert res.json['leak_date'] is not None

    def test_create_credential_invalid_data(self, test_client, workspace):
        # Missing required fields
        credential_data = {
            'owned': True,
            'workspace': workspace.name
        }
        res = test_client.post(self.url(workspace=workspace), data=credential_data)
        assert res.status_code == 400

    def test_credential_link_to_vulnerability(self, test_client, workspace, session):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.commit()

        credential_data = {
            'username': 'vulnuser',
            'password': 'vulnpass',
            'endpoint': 'vuln.example.com',
            'owned': True,
            'workspace': workspace.name,
            'vulnerabilities': [vuln.id]
        }

        res = test_client.post(self.url(workspace=workspace), data=credential_data)

        assert res.status_code == 201
        assert len(res.json['vulnerabilities']) == 1
        assert res.json['vulnerabilities'][0]['_id'] == vuln.id

    def test_envelope_list(self, test_client, workspace, session):
        credentials = CredentialFactory.create_batch(5, workspace=workspace)
        session.add_all(credentials)
        session.commit()

        res = test_client.get(self.url(workspace=workspace))
        assert res.status_code == 200
        assert 'rows' in res.json
        assert 'count' in res.json
        assert res.json['count'] == 10
        assert len(res.json['rows']) == 10
        for cred_envelope in res.json['rows']:
            assert 'id' in cred_envelope
            assert 'key' in cred_envelope
            assert 'value' in cred_envelope

    def test_update_credential(self, test_client, workspace, session):
        credential = CredentialFactory.create(workspace=workspace)
        session.add(credential)
        session.commit()

        data = {
            'username': 'updated_user',
            'password': 'updated_pass',
            'endpoint': 'updated.example.com'
        }

        res = test_client.put(self.url(workspace=workspace) + f"/{credential.id}", data=data)

        assert res.status_code == 200
        assert res.json['username'] == 'updated_user'
        assert res.json['password'] == 'updated_pass'
        assert res.json['endpoint'] == 'updated.example.com'

    def test_patch_credential_vulnerabilities(self, test_client, workspace, session):
        # Create initial vulnerabilities
        vuln1 = VulnerabilityFactory.create(workspace=workspace)
        vuln2 = VulnerabilityFactory.create(workspace=workspace)
        vuln3 = VulnerabilityFactory.create(workspace=workspace)
        session.commit()

        # Create credential with vuln1 linked
        credential = CredentialFactory.create(workspace=workspace)
        credential.vulnerabilities.append(vuln1)
        session.commit()

        # Verify initial state
        res = test_client.get(self.url(workspace=workspace) + f"/{credential.id}")
        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 1
        assert res.json['vulnerabilities'][0]['_id'] == vuln1.id

        # Test 1: Add vuln2 (should have vuln1 and vuln2)
        patch_data = {
            'vulnerabilities': [vuln1.id, vuln2.id]
        }
        res = test_client.patch(self.url(workspace=workspace) + f"/{credential.id}", data=patch_data)
        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 2
        vuln_ids = [v['_id'] for v in res.json['vulnerabilities']]
        assert vuln1.id in vuln_ids
        assert vuln2.id in vuln_ids

        # Check if the credentials are in the vulnerabilities
        assert credential in vuln1.credentials
        assert credential in vuln2.credentials

        # Test 2: Replace with only vuln3 (should have only vuln3)
        patch_data = {
            'vulnerabilities': [vuln3.id]
        }
        res = test_client.patch(self.url(workspace=workspace) + f"/{credential.id}", data=patch_data)
        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 1
        assert res.json['vulnerabilities'][0]['_id'] == vuln3.id

        # Test 3: Empty the vulnerabilities list (should have no vulns)
        patch_data = {
            'vulnerabilities': []
        }
        res = test_client.patch(self.url(workspace=workspace) + f"/{credential.id}", data=patch_data)
        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 0

    def test_unique_constraint(self, test_client, workspace):
        # Create a credential
        credential_data = {
            'username': 'uniqueuser',
            'password': 'uniquepass',
            'endpoint': 'unique.example.com',
            'owned': True,
            'workspace': workspace.name
        }
        res = test_client.post(self.url(workspace=workspace), data=credential_data)
        assert res.status_code == 201

        # Attempt to create a duplicate credential
        duplicate_data = {
            'username': 'uniqueuser',
            'password': 'uniquepass',
            'endpoint': 'unique.example.com',
            'owned': True,
            'workspace': workspace.name
        }
        res = test_client.post(self.url(workspace=workspace), data=duplicate_data)
        assert res.status_code == 409

    def test_credential_filter(self, test_client, workspace, session):
        # Create some credentials
        credential1 = CredentialFactory.create(workspace=workspace, username='testuser1')
        credential2 = CredentialFactory.create(workspace=workspace, username='testuser2')
        session.add_all([credential1, credential2])
        session.commit()

        # Test filtering by username
        res = test_client.get(self.url(workspace=workspace) + '/filter?q={"filters":[{"name":"username","op":"eq","val":"testuser1"}]}')
        assert res.status_code == 200
        assert len(res.json['rows']) == 1
        assert res.json['rows'][0]['value']['username'] == 'testuser1'

    def test_credential_filter_export_csv(self, test_client, workspace, session):
        # Create some credentials
        credential1 = CredentialFactory.create(workspace=workspace, username='testuser1', password='testpass', endpoint='test.example.com')
        credential2 = CredentialFactory.create(workspace=workspace, username='testuser2')
        session.add_all([credential1, credential2])
        session.commit()

        # Test filtering by username and exporting to CSV
        res = test_client.get(self.url(workspace=workspace) + '/filter?q={"filters":[{"name":"username","op":"eq","val":"testuser1"}]}&export_csv=true')
        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'text/csv; charset=utf-8'
        _decoded_data = res.data.decode('utf-8')
        assert 'attachment; filename=Faraday-SR-Context.csv' in res.headers['Content-Disposition']
        assert 'username,password,endpoint' in _decoded_data
        assert 'testuser1,testpass,test.example.com' in _decoded_data
        assert 'testuser2' not in _decoded_data

    @pytest.mark.skip(reason="Figure out to make this test work")
    def test_bulk_create_credentials_from_csv(self, test_client, workspace, session):
        # get csv file from ./data/credential_test_success.csv
        csv_file_path = (Path(__file__).parent / 'data/credential_test_success.csv')
        with open(csv_file_path) as csv_file:
            csv_content = csv_file.read()
        csv_file = io.StringIO(csv_content)
        csv_file.name = 'credentials.csv'
        csv_file.seek(0)
        # Prepare the request data
        data = {
            'file': csv_file
        }
        # Set the content type to multipart/form-data
        headers = {
            'Content-Type': 'multipart/form-data'
        }

        # Send the request
        res = test_client.post(self.url(workspace=workspace) + '/bulk_create', data=data, headers=headers)

        # Check response
        assert res.status_code == 201
        assert 'message' in res.json
        assert 'CSV imported successfully' in res.json['message']
        assert 'Created: 3 credentials' in res.json['message']

        # Verify credentials were created in the database
        credentials = session.query(Credential).filter(
            Credential.workspace_id == workspace.id
        ).all()

        # Find our imported credentials
        csv_credentials = [c for c in credentials if c.username.startswith('csv_user')]
        assert len(csv_credentials) == 3

        # Verify the leak dates were properly set
        for cred in csv_credentials:
            if cred.username == 'csv_user1':
                assert cred.leak_date.strftime('%Y-%m-%d') == '2023-01-01'
            elif cred.username == 'csv_user2':
                assert cred.leak_date is None
            elif cred.username == 'csv_user3':
                assert cred.leak_date.strftime('%Y-%m-%d') == '2023-03-15'

            # Verify all credentials have owned=False by default
            assert cred.owned is False
