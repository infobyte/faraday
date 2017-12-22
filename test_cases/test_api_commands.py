#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""
import datetime
import pytest
import time

from test_cases import factories
from test_api_workspaced_base import API_PREFIX, ReadOnlyAPITests
from server.models import (
    Command,
    Workspace,
    Vulnerability)
from server.api.modules.commandsrun import CommandView
from server.api.modules.workspaces import WorkspaceView
from test_cases.factories import VulnerabilityFactory, EmptyCommandFactory, CommandObjectFactory, HostFactory, \
    WorkspaceFactory, ServiceFactory


# Note: because of a bug with pytest, I can't simply mark TestListCommandView
# with @pytest.mark.skip. I had to made it inherit from object instad of
# ReadOnlyAPITests, and to manually skip the extra tests inside the class.
# See https://docs.pytest.org/en/latest/skipping.html#skip-all-test-functions-of-a-class-or-module
# and https://github.com/pytest-dev/pytest/issues/568 for more information

@pytest.mark.usefixtures('logged_user')
class TestListCommandView(ReadOnlyAPITests):
    model = Command
    factory = factories.CommandFactory
    api_endpoint = 'commands'
    view_class = CommandView

    def test_backwards_compatibility_list(self, test_client, second_workspace, session):
        self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'commands' in res.json
        for command in res.json['commands']:
            assert set([u'id', u'key', u'value']) == set(command.keys())
            object_properties = [
                u'_id',
                u'command',
                u'duration',
                u'hostname',
                u'ip',
                u'itime',
                u'params',
                u'user',
                u'workspace'
            ]
            assert command['value']['workspace'] == self.workspace.name
            assert set(object_properties) == set(command['value'].keys())

    def test_activity_feed(self, session, test_client):
        command = self.factory.create()
        another_command = EmptyCommandFactory.create(workspace=command.workspace)
        vuln = session.query(Vulnerability).get(command.command_objects[0].object_id)
        session.flush()
        CommandObjectFactory.create(
            command=another_command,
            object_type='vulnerability',
            object_id=vuln.id,
            workspace=command.workspace
        )
        CommandObjectFactory.create(
            command=another_command,
            object_type='host',
            object_id=vuln.host.id,
            workspace=command.workspace
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200

        assert filter(lambda stats: stats['_id'] == command.id, res.json) == [{u'_id': command.id,
                                                                               u'command': command.command,
                                                                               u'import_source': u'shell',
                                                                               u'user': command.user,
                                                                               u'date': time.mktime(command.start_date.timetuple()) * 1000,
                                                                               u'params': command.params,
                                                                               u'hosts_count': 1,
                                                                               u'services_count': 0,
                                                                               u'vulnerabilities_count': 1,
                                                                               u'criticalIssue': 0}]

        assert filter(lambda stats: stats['_id'] == another_command.id, res.json) == [{
                                                                                u'_id': another_command.id,
                                                                                u'command': another_command.command,
                                                                                u'import_source': u'shell',
                                                                                u'user': another_command.user,
                                                                                u'date': time.mktime(another_command.start_date.timetuple()) * 1000,
                                                                                u'params': another_command.params,
                                                                                u'hosts_count': 0,
                                                                                u'services_count': 0,
                                                                                u'vulnerabilities_count': 0,
                                                                                u'criticalIssue': 0}]

    def test_verify_created_critical_vulns_is_correctly_showing_sum_values(self, session, test_client):
        workspace = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=workspace)
        host = HostFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(severity='critical', workspace=workspace, host=host, service=None)
        vuln_med = VulnerabilityFactory.create(severity='medium', workspace=workspace, host=host, service=None)
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
            object_id=vuln.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_med.id,
            workspace=workspace
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200
        assert res.json == [
                            {u'_id': command.id,
                             u'command': command.command,
                             u'import_source': u'shell',
                             u'user': command.user,
                             u'date': time.mktime(command.start_date.timetuple()) * 1000,
                             u'params': command.params,
                             u'hosts_count': 1,
                             u'services_count': 0,
                             u'vulnerabilities_count': 2,
                             u'criticalIssue': 1}
                            ]

    def test_verify_created_vulns_with_host_and_service_verification(self, session, test_client):
        workspace = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=workspace)
        host = HostFactory.create(workspace=workspace)
        service = ServiceFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(severity='critical', workspace=workspace, host=host, service=None)
        vuln_med = VulnerabilityFactory.create(severity='medium', workspace=workspace, service=service, host=None)
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
            object_id=vuln.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='service',
            object_id=service.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=command,
            object_type='vulnerability',
            object_id=vuln_med.id,
            workspace=workspace
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200
        assert res.json == [{u'_id': command.id,
             u'command': command.command,
             u'import_source': u'shell',
             u'user': command.user,
             u'date': time.mktime(command.start_date.timetuple()) * 1000,
             u'params': command.params,
             u'hosts_count': 1,
             u'services_count': 1,
             u'vulnerabilities_count': 2,
             u'criticalIssue': 1}
        ]

    def test_multiple_commands_executed_with_same_objects_found(self, session, test_client):
        """
            This text verifies that multiple command does not affect activity feed counters.
        """
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(severity='low', workspace=workspace, host=host, service=None)
        service = ServiceFactory.create(workspace=workspace)
        commands = []
        in_the_middle_commands = []
        first_command = None
        for index in range(0, 10):

            command = EmptyCommandFactory.create(workspace=workspace)
            commands.append(command)
            if index > 0:
                # in the middle commands should not affect counters (should be at 0)
                in_the_middle_commands.append(command)
            else:
                first_command = command
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
                object_id=vuln.id,
                workspace=workspace
            )
        # This command will change activity feed counters
        vuln_med = VulnerabilityFactory.create(severity='medium', workspace=workspace, service=service, host=None)
        session.flush()
        last_command = EmptyCommandFactory.create(workspace=workspace)
        CommandObjectFactory.create(
            command=last_command,
            object_type='service',
            object_id=service.id,
            workspace=workspace
        )
        CommandObjectFactory.create(
            command=last_command,
            object_type='vulnerability',
            object_id=vuln_med.id,
            workspace=workspace
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200
        raw_first_command = filter(lambda comm: comm['_id'] == commands[0].id, res.json)

        assert raw_first_command.pop() == {
            u'_id': first_command.id,
            u'command': first_command.command,
            u'import_source': u'shell',
            u'user': first_command.user,
            u'date': time.mktime(first_command.start_date.timetuple()) * 1000,
            u'params': first_command.params,
            u'hosts_count': 1,
            u'services_count': 0,
            u'vulnerabilities_count': 1,
            u'criticalIssue': 0
        }

        for in_the_middle_command in in_the_middle_commands:
            raw_in_the_middle_command = filter(lambda comm: comm['_id'] == in_the_middle_command.id, res.json)
            assert raw_in_the_middle_command.pop() == {u'_id': in_the_middle_command.id,
                                       u'command': in_the_middle_command.command,
                                       u'import_source': u'shell',
                                       u'user': in_the_middle_command.user,
                                       u'date': time.mktime(in_the_middle_command.start_date.timetuple()) * 1000,
                                       u'params': in_the_middle_command.params,
                                       u'hosts_count': 0,
                                       u'services_count': 0,
                                       u'vulnerabilities_count': 0,
                                       u'criticalIssue': 0}

        # new command must create new service and vuln
        raw_last_command = filter(lambda comm: comm['_id'] == last_command.id, res.json)
        assert raw_last_command.pop() == {u'_id': last_command.id,
                                       u'command': last_command.command,
                                       u'import_source': u'shell',
                                       u'user': last_command.user,
                                       u'date': time.mktime(last_command.start_date.timetuple()) * 1000,
                                       u'params': last_command.params,
                                       u'hosts_count': 0,
                                       u'services_count': 1,
                                       u'vulnerabilities_count': 1,
                                       u'criticalIssue': 0}

    def test_sub_second_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'] == 0.442406

    def test_more_than_one_second_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 29, 20, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'] == 1.442406

    def test_more_than_one_hour_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 28, 20, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'] == 61.442406

    def test_create_command(self, test_client):
        raw_data ={
            'command': 'Import Nessus:',
            'duration': None,
            'hostname': 'mandarina',
            'ip': '192.168.20.53',
            'itime': 1511387720.048548,
            'params': u'/home/lcubo/.faraday/report/airbnb/nessus_report_Remote.nessus',
            'user': 'lcubo'
        }

        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201


    def test_update_command(self, test_client, session):
        command = self.factory()
        session.commit()
        raw_data ={
            'command': 'Import Nessus:',
            'duration': 120,
            'hostname': 'mandarina',
            'ip': '192.168.20.53',
            'itime': 1511387720.048548,
            'params': u'/home/lcubo/.faraday/report/airbnb/nessus_report_Remote.nessus',
            'user': 'lcubo'
        }

        res = test_client.put(self.url(command, workspace=command.workspace), data=raw_data)
        assert res.status_code == 200
        updated_command = self.model.query.get(command.id)
        assert updated_command.end_date == datetime.datetime.fromtimestamp(1511387720.048548) + datetime.timedelta(seconds=120)