'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest
from io import BytesIO

from tests.conftest import TEST_DATA_PATH
from tests.factories import WorkspaceFactory

from faraday.server.threads.reports_processor import REPORTS_QUEUE

from faraday.server.models import Host, Service, Command


@pytest.mark.usefixtures('logged_user')
class TestFileUpload:

    def test_file_upload(self, test_client, session, csrf_token, logged_user):
        REPORTS_QUEUE.queue.clear()
        ws = WorkspaceFactory.create(name="abc")
        session.add(ws)
        session.commit()
        path = TEST_DATA_PATH / 'nmap_plugin_with_api.xml'

        with path.open('rb') as report:
            file_contents = report.read()
        data = {
            'file': (BytesIO(file_contents), 'nmap_report.xml'),
            'csrf_token': csrf_token,
            'ignore_info': False,
            'dns_resolution': True
        }

        res = test_client.post(
                f'/v3/ws/{ws.name}/upload_report',
                data=data,
                use_json_data=False)

        assert res.status_code == 200
        assert len(REPORTS_QUEUE.queue) == 1
        queue_elem = REPORTS_QUEUE.get_nowait()
        assert queue_elem[0] == ws.name
        assert queue_elem[3].lower() == "nmap"
        assert queue_elem[4] == logged_user.id
        assert queue_elem[5] is False
        assert queue_elem[6] is True

        # I'm testing a method which lost referene of workspace and logged_user within the test
        ws_id = ws.id
        logged_user_id = logged_user.id

        from faraday.server.threads.reports_processor import process_report
        process_report(queue_elem[0], queue_elem[1],
                                    queue_elem[2], queue_elem[3],
                                    queue_elem[4], queue_elem[5], queue_elem[6])
        command = Command.query.filter(Command.workspace_id == ws_id).one()
        assert command
        assert command.creator_id == logged_user_id
        assert command.id == res.json["command_id"]
        host = Host.query.filter(Host.workspace_id == ws_id).first()
        assert host
        assert host.creator_id == logged_user_id
        service = Service.query.filter(Service.workspace_id == ws_id).first()
        assert service
        assert service.creator_id == logged_user_id

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
