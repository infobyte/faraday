#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

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

    @pytest.mark.usefixtures('ignore_nplusone')
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

        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(severity='low', workspace=workspace, host=host, service=None)
        service = ServiceFactory.create(workspace=workspace)
        commands = []
        for index in range(0, 10):
            command = EmptyCommandFactory.create(workspace=workspace)
            commands.append(command)

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
        vuln_med = VulnerabilityFactory.create(severity='medium', workspace=workspace, service=service, host=None)
        session.flush()
        command = EmptyCommandFactory.create(workspace=workspace)
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
        assert res.json[0] == {u'_id': commands[0].id,
                               u'command': commands[0].command,
                               u'import_source': u'shell',
                               u'user': commands[0].user,
                               u'date': time.mktime(commands[0].start_date.timetuple()) * 1000,
                               u'params': commands[0].params,
                               u'hosts_count': 1,
                               u'services_count': 0,
                               u'vulnerabilities_count': 1,
                               u'criticalIssue': 0}

        for index in range(1, 10):
            assert res.json[index] == {u'_id': commands[index].id,
                                       u'command': commands[index].command,
                                       u'import_source': u'shell',
                                       u'user': commands[index].user,
                                       u'date': time.mktime(commands[index].start_date.timetuple()) * 1000,
                                       u'params': commands[index].params,
                                       u'hosts_count': 0,
                                       u'services_count': 0,
                                       u'vulnerabilities_count': 0,
                                       u'criticalIssue': 0}

        # new command must create new service and vuln
        assert res.json[10] == {u'_id': command.id,
                                       u'command': command.command,
                                       u'import_source': u'shell',
                                       u'user': command.user,
                                       u'date': time.mktime(command.start_date.timetuple()) * 1000,
                                       u'params': command.params,
                                       u'hosts_count': 0,
                                       u'services_count': 1,
                                       u'vulnerabilities_count': 1,
                                       u'criticalIssue': 0}
