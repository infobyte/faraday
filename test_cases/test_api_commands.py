#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest
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
# class TestListCommandView(ReadOnlyAPITests):  # TODO: change to this!!!
class TestListCommandView(object):
    model = Command
    factory = factories.CommandFactory
    api_endpoint = 'commands'
    view_class = CommandView

    @pytest.mark.skip(reason='refactor needed to adapt new m2m model')
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

    @pytest.mark.skip(reason='refactor needed to adapt new m2m model')
    def test_activity_feed(self, session, test_client):
        command = self.factory.create()
        another_command = EmptyCommandFactory.create(workspace=command.workspace)
        vuln = session.query(Vulnerability).get(command.command_objects[0].object_id)
        session.flush()
        CommandObjectFactory.create(
            command=another_command,
            object_type='Vulnerability',
            object_id=vuln.id
        )
        CommandObjectFactory.create(
            command=another_command,
            object_type='Host',
            object_id=vuln.host.id
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200

        assert filter(lambda stats: stats['command'] == command.id, res.json) == [{u'command': command.id,
                                                                                  u'sum_created_hosts': 1,
                                                                                  u'sum_created_services': 0,
                                                                                  u'sum_created_vulnerabilities': 1,
                                                                                  u'sum_created_vulnerabilities_web': 0,
                                                                                  u'sum_created_vulnerability_critical': 0}]

        assert filter(lambda stats: stats['command'] == another_command.id, res.json) == [{u'command': another_command.id,
                                                                                          u'sum_created_hosts': 0,
                                                                                          u'sum_created_services': 0,
                                                                                          u'sum_created_vulnerabilities': 0,
                                                                                          u'sum_created_vulnerabilities_web': 0,
                                                                                          u'sum_created_vulnerability_critical': 0}]

    @pytest.mark.skip(reason='refactor needed to adapt new m2m model')
    def test_verify_created_critical_vulns_is_correctly_showing_sum_values(self, session, test_client):
        workspace = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=workspace)
        host = HostFactory.create(workspace=workspace)
        vuln = VulnerabilityFactory.create(severity='critical', workspace=workspace, host=host, service=None)
        vuln_med = VulnerabilityFactory.create(severity='medium', workspace=workspace, host=host, service=None)
        session.flush()
        CommandObjectFactory.create(
            command=command,
            object_type='Host',
            object_id=host.id
        )
        CommandObjectFactory.create(
            command=command,
            object_type='Vulnerability',
            object_id=vuln.id
        )
        CommandObjectFactory.create(
            command=command,
            object_type='Vulnerability',
            object_id=vuln_med.id
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200
        assert res.json == [{u'command': command.id,
                             u'sum_created_hosts': 1,
                             u'sum_created_services': 0,
                             u'sum_created_vulnerabilities': 2,
                             u'sum_created_vulnerabilities_web': 0,
                             u'sum_created_vulnerability_critical': 1
                             }]

    @pytest.mark.skip(reason='refactor needed to adapt new m2m model')
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
            object_type='Host',
            object_id=host.id
        )
        CommandObjectFactory.create(
            command=command,
            object_type='Vulnerability',
            object_id=vuln.id
        )
        CommandObjectFactory.create(
            command=command,
            object_type='Service',
            object_id=service.id
        )
        CommandObjectFactory.create(
            command=command,
            object_type='Vulnerability',
            object_id=vuln_med.id
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200
        assert res.json == [{u'command': command.id,
                             u'sum_created_hosts': 1,
                             u'sum_created_services': 1,
                             u'sum_created_vulnerabilities': 2,
                             u'sum_created_vulnerabilities_web': 0,
                             u'sum_created_vulnerability_critical': 1
                             }]

    @pytest.mark.skip(reason='refactor needed to adapt new m2m model')
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
                object_type='Host',
                object_id=host.id
            )
            CommandObjectFactory.create(
                command=command,
                object_type='Vulnerability',
                object_id=vuln.id
            )
        vuln_med = VulnerabilityFactory.create(severity='medium', workspace=workspace, service=service, host=None)
        session.flush()
        command = EmptyCommandFactory.create(workspace=workspace)
        CommandObjectFactory.create(
            command=command,
            object_type='Service',
            object_id=service.id
        )
        CommandObjectFactory.create(
            command=command,
            object_type='Vulnerability',
            object_id=vuln_med.id
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200
        assert res.json[0] == {u'command': commands[0].id,
                             u'sum_created_hosts': 1,
                             u'sum_created_services': 0,
                             u'sum_created_vulnerabilities': 1,
                             u'sum_created_vulnerabilities_web': 0,
                             u'sum_created_vulnerability_critical': 0
                             }
        for index in range(1, 10):
            assert res.json[index] == {u'command': commands[index].id,
                                   u'sum_created_hosts': 0,
                                   u'sum_created_services': 0,
                                   u'sum_created_vulnerabilities': 0,
                                   u'sum_created_vulnerabilities_web': 0,
                                   u'sum_created_vulnerability_critical': 0
                                   }

        # new command must create new service and vuln
        assert res.json[10] == {u'command': command.id,
                               u'sum_created_hosts': 0,
                               u'sum_created_services': 1,
                               u'sum_created_vulnerabilities': 1,
                               u'sum_created_vulnerabilities_web': 0,
                               u'sum_created_vulnerability_critical': 0
                               }
