import datetime
import io
from faraday.server.models import Credential
from faraday.server.api.modules.credentials import CredentialView
from tests.test_api_workspaced_base import ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin
from tests.factories import CredentialFactory, VulnerabilityFactory, VulnerabilityWebFactory
from tests.conftest import TEST_DATA_PATH
import pytest

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

    def test_credential_link_to_web_vulnerability(self, test_client, workspace, session):
        vuln = VulnerabilityWebFactory.create(workspace=workspace)
        session.commit()

        credential_data = {
            'username': 'webvulnuser',
            'password': 'webvulnpass',
            'endpoint': 'webvuln.example.com',
            'owned': True,
            'workspace': workspace.name,
            'vulnerabilities': [vuln.id]
        }
        res = test_client.post(self.url(workspace=workspace), data=credential_data)
        assert res.status_code == 201
        assert len(res.json['vulnerabilities']) == 1
        assert res.json['vulnerabilities'][0]['_id'] == vuln.id

    def test_credential_link_to_vulnerability_different_workspace(self, test_client, workspace, session, second_workspace):
        vuln = VulnerabilityFactory.create(workspace=second_workspace)
        session.commit()

        credential_data = {
            'username': 'crosswsuser',
            'password': 'crosswspass',
            'endpoint': 'crossws.example.com',
            'owned': True,
            'workspace': workspace.name,
            'vulnerabilities': [vuln.id]
        }

        res = test_client.post(self.url(workspace=workspace), data=credential_data)

        assert res.status_code == 201
        assert len(res.json['vulnerabilities']) == 0

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

    def test_update_credential_with_vulnerability_different_workspace(self, test_client, workspace, session, second_workspace):
        credential = CredentialFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(workspace=second_workspace)
        session.add(credential)
        session.commit()

        data = {
            'username': 'updated_user',
            'password': 'updated_pass',
            'endpoint': 'updated.example.com',
            'vulnerabilities': [vuln.id]
        }

        res = test_client.put(self.url(workspace=workspace) + f"/{credential.id}", data=data)

        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 0

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

    def test_patch_credential_with_mixed_workspace_vulnerabilities(self, test_client, workspace, session, second_workspace):
        vuln1 = VulnerabilityFactory.create(workspace=workspace)
        vuln2 = VulnerabilityFactory.create(workspace=second_workspace)
        session.commit()

        credential = CredentialFactory.create(workspace=workspace)
        session.add(credential)
        session.commit()

        patch_data = {
            'vulnerabilities': [vuln1.id, vuln2.id]
        }

        res = test_client.patch(self.url(workspace=workspace) + f"/{credential.id}", data=patch_data)

        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 1
        assert res.json['vulnerabilities'][0]['_id'] == vuln1.id

    def test_bulk_update_with_cross_workspace_vulnerabilities(self, test_client, workspace, session, second_workspace):
        credential1 = CredentialFactory.create(workspace=workspace)
        credential2 = CredentialFactory.create(workspace=workspace)
        vuln1 = VulnerabilityFactory.create(workspace=workspace)
        vuln2 = VulnerabilityFactory.create(workspace=second_workspace)
        session.add_all([credential1, credential2, vuln1, vuln2])
        session.commit()

        data = {
            'ids': [credential1.id, credential2.id],
            'vulnerabilities': [vuln1.id, vuln2.id]
        }

        res = test_client.patch(self.url(workspace=workspace), data=data)

        assert res.status_code == 200

        # Verify that only vuln1 was associated with credentials
        cred = Credential.query.get(credential1.id)
        assert len(cred.vulnerabilities) == 1
        assert cred.vulnerabilities[0].id == vuln1.id

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

    @pytest.mark.parametrize('field', [
        ['username', 'eq', 'username'],
        ['password', 'eq', 'password'],
        ['endpoint', 'eq', 'endpoint'],
        ['owned', 'eq', 'false'],
        ['leak_date', '>=', '2023-10-01'],
        ])
    def test_credential_filter_all_fields(self, test_client, workspace, session, field):
        session.query(Credential).delete()
        session.commit()
        # Create a credential with the specified field
        credential = CredentialFactory.create(workspace=workspace, username='username', password='password', endpoint='endpoint', owned=False, leak_date='2023-10-01')
        session.add(credential)
        session.commit()

        res = test_client.get(self.url(workspace=workspace) + f'/filter?q={{"filters":[{{"name":"{field[0]}","op":"{field[1]}","val":"{field[2]}"}}]}}')
        assert res.status_code == 200
        assert len(res.json['rows']) == 1
        if field[0] == 'leak_date':
            field[2] = field[2] + 'T00:00:00+00:00'
        if field[0] == 'owned':
            field[2] = False
        assert res.json['rows'][0]['value'][field[0]] == field[2]

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
        assert f'attachment; filename=Faraday-{workspace.name}-Credentials.csv' in res.headers['Content-Disposition']
        assert 'username,password,endpoint,leak_date' in _decoded_data
        assert 'testuser1,testpass,test.example.com' in _decoded_data
        assert 'testuser2' not in _decoded_data

    def test_bulk_create_credentials_from_csv(self, test_client, workspace, session, csrf_token):
        # Get the CSV file path
        path = TEST_DATA_PATH / "credential_test_success.csv"

        with path.open('r') as csv_file:
            file_contents = csv_file.read().encode('utf-8')

        data = {
            'file': (io.BytesIO(file_contents), 'credentials.csv'),
            'csrf_token': csrf_token
        }

        res = test_client.post(
                self.url(workspace=workspace) + '/import_csv',
                data=data,
                use_json_data=False
        )

        assert res.status_code == 201
        assert res.json['message'] == 'CSV imported successfully - Created: 2 credentials, Skipped: 0 credentials'

        creds = Credential.query.filter_by(workspace=workspace).all()
        assert len(creds) == 7

    def test_bulk_create_credentials_from_csv_with_vulns_ids(self, test_client, workspace, session, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()
        # Get the CSV file path
        path = TEST_DATA_PATH / "credential_test_success.csv"

        with path.open('r') as csv_file:
            file_contents = csv_file.read().encode('utf-8')

        data = {
            'file': (io.BytesIO(file_contents), 'credentials.csv'),
            'csrf_token': csrf_token,
            'vulns_ids': f"{vuln.id}"
        }

        res = test_client.post(
                self.url(workspace=workspace) + '/import_csv',
                data=data,
                use_json_data=False
        )

        assert res.status_code == 201
        assert res.json['message'] == 'CSV imported successfully - Created: 2 credentials, Skipped: 0 credentials'

        creds = Credential.query.filter_by(workspace=workspace).all()
        assert creds[5].vulnerabilities[0].id == vuln.id
        assert creds[6].vulnerabilities[0].id == vuln.id
        assert len(creds) == 7

    def test_bulk_create_credentials_from_csv_with_vulns_ids_diff_ws(self, test_client, workspace, session, csrf_token, second_workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        vuln2 = VulnerabilityFactory.create(workspace=second_workspace)
        session.add(vuln)
        session.add(vuln2)
        session.commit()
        # Get the CSV file path
        path = TEST_DATA_PATH / "credential_test_success.csv"

        with path.open('r') as csv_file:
            file_contents = csv_file.read().encode('utf-8')

        data = {
            'file': (io.BytesIO(file_contents), 'credentials.csv'),
            'csrf_token': csrf_token,
            'vulns_ids': f"{vuln.id},{vuln2.id}"
        }

        res = test_client.post(
                self.url(workspace=workspace) + '/import_csv',
                data=data,
                use_json_data=False
        )

        assert res.status_code == 201
        assert res.json['message'] == 'CSV imported successfully - Created: 2 credentials, Skipped: 0 credentials'

        creds = Credential.query.filter_by(workspace=workspace).all()
        assert creds[-2].vulnerabilities[0].id == vuln.id
        assert creds[-1].vulnerabilities[0].id == vuln.id
        assert len(creds) == 7
        assert len(vuln2.credentials) == 0
        assert len(vuln.credentials) == 2

    def test_bulk_create_credentials_from_csv_fail_duplicate(self, test_client, workspace, session, csrf_token):
        # Get the CSV file path
        path = TEST_DATA_PATH / "credential_test_fail_duplicate.csv"

        with path.open('r') as csv_file:
            file_contents = csv_file.read().encode('utf-8')

        data = {
            'file': (io.BytesIO(file_contents), 'credentials.csv'),
            'csrf_token': csrf_token
        }

        res = test_client.post(
                self.url(workspace=workspace) + '/import_csv',
                data=data,
                use_json_data=False
        )

        assert res.status_code == 201
        assert res.json['message'] == 'CSV imported successfully - Created: 2 credentials, Skipped: 1 credentials'

        creds = Credential.query.filter_by(workspace=workspace).all()
        assert len(creds) == 7

    def test_bulk_create_empty_leak_date_csv(self, test_client, workspace, session, csrf_token):
        # Get the CSV file path
        path = TEST_DATA_PATH / "credential_test_success_empty_leak_date.csv"

        with path.open('r') as csv_file:
            file_contents = csv_file.read().encode('utf-8')

        data = {
            'file': (io.BytesIO(file_contents), 'credentials.csv'),
            'csrf_token': csrf_token
        }

        res = test_client.post(
                self.url(workspace=workspace) + '/import_csv',
                data=data,
                use_json_data=False
        )

        assert res.status_code == 201
        assert res.json['message'] == 'CSV imported successfully - Created: 2 credentials, Skipped: 0 credentials'

        creds = Credential.query.filter_by(workspace=workspace).all()
        assert len(creds) == 7
