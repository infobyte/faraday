'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

"""Tests for many API endpoints that do not depend on workspace_name"""
from posixpath import join as urljoin
import datetime
import pytest
import time

from tests import factories
from tests.test_api_workspaced_base import ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin
from faraday.server.models import (
    Command,
    Vulnerability)
from faraday.server.api.modules.commandsrun import CommandView
from tests.factories import VulnerabilityFactory, EmptyCommandFactory, CommandObjectFactory, HostFactory, \
    WorkspaceFactory, ServiceFactory, RuleExecutionFactory, AgentExecutionFactory


# Note: because of a bug with pytest, I can't simply mark TestListCommandView
# with @pytest.mark.skip. I had to made it inherit from object instad of
# ReadOnlyAPITests, and to manually skip the extra tests inside the class.
# See https://docs.pytest.org/en/latest/skipping.html#skip-all-test-functions-of-a-class-or-module
# and https://github.com/pytest-dev/pytest/issues/568 for more information

@pytest.mark.usefixtures('logged_user')
class TestListCommandView(ReadWriteAPITests, BulkUpdateTestsMixin, BulkDeleteTestsMixin):
    model = Command
    factory = factories.CommandFactory
    api_endpoint = 'commands'
    view_class = CommandView
    patchable_fields = ["ip"]

    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.usefixtures('mock_envelope_list')
    def test_list_retrieves_all_items_from_workspace(self, test_client,
                                                     second_workspace,
                                                     session):
        super().test_list_retrieves_all_items_from_workspace(test_client, second_workspace, session)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_backwards_compatibility_list(self, test_client, second_workspace, session):
        self.factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert 'commands' in res.json
        for command in res.json['commands']:
            assert {'id', 'key', 'value'} == set(command.keys())
            object_properties = [
                '_id',
                'command',
                'duration',
                'hostname',
                'ip',
                'itime',
                'params',
                'user',
                'workspace',
                'tool',
                'import_source',
                'creator',
                'metadata'
            ]
            assert command['value']['workspace'] == self.workspace.name
            assert set(object_properties) == set(command['value'].keys())

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_can_list_readonly(self, test_client, session):
        super().test_can_list_readonly(test_client, session)

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

        res = test_client.get(urljoin(self.url(workspace=command.workspace), 'activity_feed'))
        assert res.status_code == 200

        assert list(filter(lambda stats: stats['_id'] == command.id, res.json)) == [
            {'_id': command.id,
             'command': command.command,
             'import_source': 'shell',
             'user': command.user,
             'date': time.mktime(command.start_date.timetuple()) * 1000,
             'params': command.params,
             'tool': command.tool,
             'hosts_count': 1,
             'services_count': 0,
             'vulnerabilities_count': 1,
             'criticalIssue': 0}]

        assert list(filter(lambda stats: stats['_id'] == another_command.id,
                           res.json)) == [{
            '_id': another_command.id,
            'command': another_command.command,
            'import_source': 'shell',
            'tool': another_command.tool,
            'user': another_command.user,
            'date': time.mktime(
                another_command.start_date.timetuple()) * 1000,
            'params': another_command.params,
            'hosts_count': 0,
            'services_count': 0,
            'vulnerabilities_count': 0,
            'criticalIssue': 0}]

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
        res = test_client.get(urljoin(self.url(workspace=command.workspace), 'activity_feed'))
        assert res.status_code == 200
        assert res.json == [
            {'_id': command.id,
             'command': command.command,
             'import_source': 'shell',
             'tool': command.tool,
             'user': command.user,
             'date': time.mktime(command.start_date.timetuple()) * 1000,
             'params': command.params,
             'hosts_count': 1,
             'services_count': 0,
             'vulnerabilities_count': 2,
             'criticalIssue': 1}
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
        res = test_client.get(urljoin(self.url(workspace=command.workspace), 'activity_feed'))
        assert res.status_code == 200
        assert res.json == [{
            '_id': command.id,
            'command': command.command,
            'import_source': 'shell',
            'tool': command.tool,
            'user': command.user,
            'date': time.mktime(command.start_date.timetuple()) * 1000,
            'params': command.params,
            'hosts_count': 1,
            'services_count': 1,
            'vulnerabilities_count': 2,
            'criticalIssue': 1}
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
        res = test_client.get(urljoin(self.url(workspace=command.workspace), 'activity_feed'))
        assert res.status_code == 200
        raw_first_command = list(filter(lambda comm: comm['_id'] == commands[0].id, res.json))

        assert raw_first_command.pop() == {
            '_id': first_command.id,
            'command': first_command.command,
            'import_source': 'shell',
            'user': first_command.user,
            'date': time.mktime(first_command.start_date.timetuple()) * 1000,
            'params': first_command.params,
            'hosts_count': 1,
            'services_count': 0,
            'vulnerabilities_count': 1,
            'tool': first_command.tool,
            'criticalIssue': 0
        }

        for in_the_middle_command in in_the_middle_commands:
            raw_in_the_middle_command = list(filter(lambda comm: comm['_id'] == in_the_middle_command.id, res.json))
            assert raw_in_the_middle_command.pop() == {'_id': in_the_middle_command.id,
                                                       'command': in_the_middle_command.command,
                                                       'import_source': 'shell',
                                                       'user': in_the_middle_command.user,
                                                       'date': time.mktime(
                                                           in_the_middle_command.start_date.timetuple()) * 1000,
                                                       'params': in_the_middle_command.params,
                                                       'hosts_count': 0,
                                                       'tool': in_the_middle_command.tool,
                                                       'services_count': 0,
                                                       'vulnerabilities_count': 0,
                                                       'criticalIssue': 0}

        # new command must create new service and vuln
        raw_last_command = list(filter(lambda comm: comm['_id'] == last_command.id, res.json))
        assert raw_last_command.pop() == {'_id': last_command.id,
                                          'command': last_command.command,
                                          'import_source': 'shell',
                                          'user': last_command.user,
                                          'date': time.mktime(last_command.start_date.timetuple()) * 1000,
                                          'params': last_command.params,
                                          'hosts_count': 0,
                                          'tool': last_command.tool,
                                          'services_count': 1,
                                          'vulnerabilities_count': 1,
                                          'criticalIssue': 0}

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_sub_second_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'] == 0.442406

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_more_than_one_second_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 29, 20, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'] == 1.442406

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_more_than_one_minute_command_returns_correct_duration_value(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 28, 20, 248433),
            end_date=datetime.datetime(2017, 11, 14, 12, 29, 21, 690839)
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'] == 61.442406

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_more_than_one_day_none_end_date_command_returns_msg(self, test_client):
        command = self.factory(
            start_date=datetime.datetime(2017, 11, 14, 12, 28, 20, 0),
            end_date=None
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'].lower() == "timeout"

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_less_than_one_day_none_end_date_command_returns_msg(self, test_client):
        command = self.factory(
            start_date=datetime.datetime.now(),
            end_date=None
        )
        res = test_client.get(self.url(workspace=command.workspace))
        assert res.status_code == 200
        assert res.json['commands'][0]['value']['duration'].lower() == "in progress"

    def test_create_command(self, test_client):
        raw_data = {
            'command': 'Import Nessus:',
            'tool': 'nessus',
            'duration': None,
            'hostname': 'mandarina',
            'ip': '192.168.20.53',
            'itime': 1511387720.048548,
            'params': '/home/lcubo/.faraday/report/airbnb/nessus_report_Remote.nessus',
            'user': 'lcubo'
        }

        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201

    def test_update_command(self, test_client, session):
        command = self.factory()
        session.commit()
        start_date = datetime.datetime.utcnow()
        raw_data = {
            'command': 'Import Nessus:',
            'tool': 'nessus',
            'duration': 120,
            'hostname': 'mandarina',
            'ip': '192.168.20.53',
            'itime': start_date.timestamp(),
            'params': '/home/lcubo/.faraday/report/airbnb/nessus_report_Remote.nessus',
            'user': 'lcubo'
        }

        res = test_client.put(self.url(command, workspace=command.workspace),
                              data=raw_data)
        assert res.status_code == 200
        updated_command = self.model.query.get(command.id)
        print(updated_command.end_date)
        assert updated_command.end_date == updated_command.start_date + datetime.timedelta(seconds=120)

    def test_delete_objects_preserve_history(self, session, test_client):

        command = EmptyCommandFactory(command='test', tool='test', workspace=self.workspace)
        host = HostFactory.create(workspace=self.workspace)
        session.add(host)
        session.commit()
        CommandObjectFactory.create(
            command=command,
            object_type='host',
            object_id=host.id,
            workspace=self.workspace
        )
        session.commit()

        res = test_client.get(f'/v3/ws/{host.workspace.name}/hosts/{host.id}')
        assert res.status_code == 200

        res = test_client.delete(f'/v3/ws/{host.workspace.name}/hosts/{host.id}')
        assert res.status_code == 204

        res = test_client.get(urljoin(self.url(workspace=command.workspace), 'activity_feed'))
        assert res.status_code == 200
        command_history = list(filter(lambda hist: hist['_id'] == command.id, res.json))
        assert len(command_history)
        command_history = command_history[0]
        assert command_history['hosts_count'] == 1
        assert command_history['tool'] == 'test'

    def test_year_is_out_range(self, test_client):
        raw_data = {
            'command': 'Import Nessus:',
            'tool': 'nessus',
            'duration': None,
            'hostname': 'mandarina',
            'ip': '192.168.20.53',
            'itime': 1511387720000.048548,
            'params': '/home/lcubo/.faraday/report/airbnb/nessus_report_Remote.nessus',
            'user': 'lcubo'
        }

        res = test_client.post(self.url(), data=raw_data)

        assert res.status_code == 400

    def test_bulk_delete_with_references(self, session, test_client):
        command_1 = EmptyCommandFactory.create(workspace=self.workspace)
        command_2 = EmptyCommandFactory.create(workspace=self.workspace)
        for i in range(3):
            CommandObjectFactory.create(
                command=command_1,
                object_type='vulnerability',
                object_id=i,
                workspace=self.workspace
            )
        for _ in range(3):
            AgentExecutionFactory.create(
                command=command_1,
            )

        for _ in range(3):
            RuleExecutionFactory.create(
                command=command_1,
            )
        session.commit()

        data = {"ids": [command_1.id, command_2.id]}
        res = test_client.delete(self.url(), data=data)
        assert res.status_code == 200
        assert res.json['deleted'] == 2
