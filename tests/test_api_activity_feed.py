'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import datetime
import pytest

from tests.factories import (WorkspaceFactory,
                             VulnerabilityFactory,
                             CommandFactory,
                             EmptyCommandFactory,
                             HostFactory,
                             ServiceFactory,
                             CommandObjectFactory)


@pytest.mark.usefixtures('logged_user')
class TestActivityFeed:

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_activity_feed(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        command = CommandFactory.create(workspace=ws, tool="nessus")
        session.add(ws)
        session.add(command)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')

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

        new_start_date = command.end_date - datetime.timedelta(days=1)
        data = {
            'command': command.command,
            'tool': command.tool,
            'itime': new_start_date.timestamp()

        }

        res = test_client.put(f'/v3/ws/{ws.name}/activities/{command.id}',
                data=data,
            )
        assert res.status_code == 200

        # Changing res.json['itime'] to timestamp format of itime
        res_itime = res.json['itime'] / 1000.0
        assert res.status_code == 200
        assert datetime.datetime.fromtimestamp(res_itime) == new_start_date

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_verify_correct_severities_sum_values(self, session, test_client):
        workspace = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=workspace)
        host = HostFactory.create(workspace=workspace)
        vuln_critical = VulnerabilityFactory.create(severity='critical', workspace=workspace, host=host, service=None)
        vuln_high = VulnerabilityFactory.create(severity='high', workspace=workspace, host=host, service=None)
        vuln_med = VulnerabilityFactory.create(severity='medium', workspace=workspace, host=host, service=None)
        vuln_med2 = VulnerabilityFactory.create(severity='medium', workspace=workspace, host=host, service=None)
        vuln_low = VulnerabilityFactory.create(severity='low', workspace=workspace, host=host, service=None)
        vuln_info = VulnerabilityFactory.create(severity='informational', workspace=workspace, host=host, service=None)
        vuln_info2 = VulnerabilityFactory.create(severity='informational', workspace=workspace, host=host, service=None)
        vuln_unclassified = VulnerabilityFactory.create(severity='unclassified', workspace=workspace, host=host, service=None)
        session.flush()
        CommandObjectFactory.create(
            command=command,
            object_type='host',
            object_id=host.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_critical.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_high.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_med.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_med2.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_low.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_info.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_info2.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_unclassified.id,
            workspace=workspace
        )
        session.commit()
        res = test_client.get(f'/v3/ws/{command.workspace.name}/activities')
        assert res.status_code == 200
        assert res.json['activities'][0]['vulnerabilities_count'] == 8
        assert res.json['activities'][0]['criticalIssue'] == 1
        assert res.json['activities'][0]['highIssue'] == 1
        assert res.json['activities'][0]['mediumIssue'] == 2
        assert res.json['activities'][0]['lowIssue'] == 1
        assert res.json['activities'][0]['infoIssue'] == 2
        assert res.json['activities'][0]['unclassifiedIssue'] == 1


class TestActivityFeedEnvelopeFilter:
    """Tests for the _envelope_list filter in ActivityFeedView.

    A command is excluded if:
      - Its 'command' field value equals the string 'error', OR
      - All three counts (hosts, services, vulnerabilities) are zero/None.
    """

    def _add_host(self, session, command, workspace):
        host = HostFactory.create(workspace=workspace)
        session.flush()
        CommandObjectFactory.create(
            command=command, object_type='host', object_id=host.id, workspace=workspace
        )
        return host

    def _add_service(self, session, command, workspace):
        service = ServiceFactory.create(workspace=workspace)
        session.flush()
        CommandObjectFactory.create(
            command=command, object_type='service', object_id=service.id, workspace=workspace
        )
        return service

    def _add_vuln(self, session, command, workspace):
        host = HostFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(workspace=workspace, host=host, service=None, severity='low')
        session.flush()
        CommandObjectFactory.create(
            command=command, object_type='vulnerability', object_id=vuln.id, workspace=workspace
        )
        return vuln

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_error_is_excluded(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws, command='error')
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert res.json['activities'] == []

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_no_data_is_excluded(self, test_client, session):
        ws = WorkspaceFactory.create()
        EmptyCommandFactory.create(workspace=ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert res.json['activities'] == []

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_error_and_data_is_excluded(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws, command='error')
        self._add_host(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert res.json['activities'] == []

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_only_host_is_included(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws)
        self._add_host(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['hosts_count'] == 1
        assert res.json['activities'][0]['services_count'] == 0
        assert res.json['activities'][0]['vulnerabilities_count'] == 0

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_only_service_is_included(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws)
        self._add_service(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['services_count'] == 1
        assert res.json['activities'][0]['hosts_count'] == 0
        assert res.json['activities'][0]['vulnerabilities_count'] == 0

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_only_vuln_is_included(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws)
        self._add_vuln(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['vulnerabilities_count'] == 1
        assert res.json['activities'][0]['hosts_count'] == 0
        assert res.json['activities'][0]['services_count'] == 0

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_host_and_service_is_included(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws)
        self._add_host(session, command, ws)
        self._add_service(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['hosts_count'] == 1
        assert res.json['activities'][0]['services_count'] == 1
        assert res.json['activities'][0]['vulnerabilities_count'] == 0

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_host_and_vuln_is_included(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws)
        self._add_host(session, command, ws)
        self._add_vuln(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['hosts_count'] == 1
        assert res.json['activities'][0]['vulnerabilities_count'] == 1
        assert res.json['activities'][0]['services_count'] == 0

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_service_and_vuln_is_included(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws)
        self._add_service(session, command, ws)
        self._add_vuln(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['services_count'] == 1
        assert res.json['activities'][0]['vulnerabilities_count'] == 1
        assert res.json['activities'][0]['hosts_count'] == 0

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_command_with_all_data_is_included(self, test_client, session):
        ws = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=ws)
        self._add_host(session, command, ws)
        self._add_service(session, command, ws)
        self._add_vuln(session, command, ws)
        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['hosts_count'] == 1
        assert res.json['activities'][0]['services_count'] == 1
        assert res.json['activities'][0]['vulnerabilities_count'] == 1

    @pytest.mark.usefixtures('logged_user', 'ignore_nplusone')
    def test_mixed_commands_only_valid_ones_returned(self, test_client, session):
        ws = WorkspaceFactory.create()

        # Should be included
        valid_cmd = EmptyCommandFactory.create(workspace=ws)
        self._add_host(session, valid_cmd, ws)

        # Should be excluded: no data
        EmptyCommandFactory.create(workspace=ws)

        # Should be excluded: command='error'
        EmptyCommandFactory.create(workspace=ws, command='error')

        session.commit()

        res = test_client.get(f'/v3/ws/{ws.name}/activities')
        assert res.status_code == 200
        assert len(res.json['activities']) == 1
        assert res.json['activities'][0]['_id'] == valid_cmd.id
