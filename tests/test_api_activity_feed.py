'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import absolute_import
from __future__ import division

import os
import pytest
from io import BytesIO
from datetime import timedelta, datetime

from tests.factories import WorkspaceFactory, VulnerabilityFactory, CommandFactory

@pytest.mark.usefixtures('logged_user')
class TestActivityFeed():

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_activity_feed(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        command = CommandFactory.create(workspace=ws, tool="nessus")
        session.add(ws)
        session.add(command)
        session.commit()

        res = test_client.get(
            '/v2/ws/{ws_name}/activities/'
                .format(ws_name=ws.name)
            )

        assert res.status_code == 200
        activities = res.json['activities'][0]
        assert activities['hosts_count'] == 1
        assert activities['vulnerabilities_count'] == 1
        assert activities['tool'] == 'nessus'


    def test_load_itime(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        command = CommandFactory.create(workspace=ws)
        session.add(ws)
        session.add(command)
        session.commit()

        # Timestamp of 14/12/2018
        itime = 1544745600.0
        data = {
            'command': command.command,
            'tool' : command.tool,
            'itime': itime

        }

        res = test_client.put(
                '/v2/ws/{ws_name}/activities/{id}/'
                .format(ws_name=ws.name, id=command.id),
                data=data,
            )
        assert res.status_code == 200

        # Changing res.json['itime'] to timestamp format of itime
        res_itime = res.json['itime'] / 1000.0
        assert res.status_code == 200
        assert res_itime == itime
