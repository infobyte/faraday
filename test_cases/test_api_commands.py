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
            assert set(object_properties) == set(command['value'].keys())

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

    def test_multiple_commands_executed_with_same_objects_found(self, session, test_client):

        workspace = WorkspaceFactory.create()
        command = EmptyCommandFactory.create(workspace=workspace)
        service = ServiceFactory.create(workspace=workspace)
        for _ in range(0, 10):
            host = HostFactory.create(workspace=workspace)
            vuln = VulnerabilityFactory.create(severity='low', workspace=workspace, host=host, service=None)
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
                             u'sum_created_hosts': 10,
                             u'sum_created_services': 1,
                             u'sum_created_vulnerabilities': 11,
                             u'sum_created_vulnerabilities_web': 0,
                             u'sum_created_vulnerability_critical': 0
                             }]
