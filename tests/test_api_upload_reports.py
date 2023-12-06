'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest
from io import BytesIO

from tests.conftest import TEST_DATA_PATH
from tests.factories import WorkspaceFactory


@pytest.mark.usefixtures('logged_user')
class TestFileUpload:

    def test_no_file_in_request(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        session.add(ws)
        session.commit()

        res = test_client.post(f'/v3/ws/{ws.name}/upload_report')

        assert res.status_code == 400

    def test_request_without_csrf_token(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        session.add(ws)
        session.commit()
        path = TEST_DATA_PATH / 'nmap_plugin_with_api.xml'

        with path.open('r') as report:
            file_contents = report.read().encode('utf-8')

        data = {
            'file': (BytesIO(file_contents), 'nmap_report.xml'),
        }

        res = test_client.post(
                f'/v3/ws/{ws.name}/upload_report',
                data=data,
                use_json_data=False)

        assert res.status_code == 403

    def test_request_with_workspace_deactivate(self, test_client, session, csrf_token):
        ws = WorkspaceFactory.create(name="abc")
        ws.active = False
        session.add(ws)
        session.commit()
        path = TEST_DATA_PATH / 'nmap_plugin_with_api.xml'

        with path.open('r') as report:
            file_contents = report.read().encode('utf-8')

        data = {
            'file': (BytesIO(file_contents), 'nmap_report.xml'),
            'csrf_token': csrf_token
        }
        res = test_client.post(
                f'/v3/ws/{ws.name}/upload_report',
                data=data,
                use_json_data=False
        )

        assert res.status_code == 403
