'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import pytest
from io import BytesIO
from mock import Mock, patch

from test_cases.factories import WorkspaceFactory
from config.configuration import getInstanceConfiguration

@pytest.mark.usefixtures('logged_user')
class TestFileUpload():

    def test_file_upload(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        session.add(ws)
        session.commit()
        path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                'data',
                'nmap_plugin_with_api.xml')

        with open(path,'r') as report:
            file_contents = report.read()
        session_response = test_client.get('/session')
        csrf_token = session_response.json.get('csrf_token')
        data = {
            'file' : (BytesIO(file_contents), 'nmap_report.xml'),
            'csrf_token' : csrf_token
        }

        res = test_client.post(
                '/v2/ws/{ws_name}/upload_report'.format(ws_name=ws.name),
                data=data,
                use_json_data=False)

        assert res.status_code == 200


    def test_no_file_in_request(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        session.add(ws)
        session.commit()

        res = test_client.post(
                '/v2/ws/{ws_name}/upload_report'.format(ws_name=ws.name))

        assert res.status_code == 400


    def test_request_without_csrf_token(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        session.add(ws)
        session.commit()
        path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                'data',
                'nmap_plugin_with_api.xml')

        with open(path,'r') as report:
            file_contents = report.read()

        data = {
            'file' : (BytesIO(file_contents), 'nmap_report.xml'),
        }

        res = test_client.post(
                '/v2/ws/{ws_name}/upload_report'.format(ws_name=ws.name),
                data=data,
                use_json_data=False)

        assert res.status_code == 403
    

    def test_request_with_workspace_deactivate(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        ws.active = False
        session.add(ws)
        session.commit()
        path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                'data',
                'nmap_plugin_with_api.xml')

        with open(path,'r') as report:
            file_contents = report.read()

        session_response = test_client.get('/session')
        csrf_token = session_response.json.get('csrf_token')
        data = {
            'file' : (BytesIO(file_contents), 'nmap_report.xml'),
            'csrf_token' : csrf_token
        }
        res = test_client.post(
                '/v2/ws/{ws_name}/upload_report'.format(ws_name=ws.name),
                data=data,
                use_json_data=False)

        assert res.status_code == 404
