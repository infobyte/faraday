#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest
from test_cases import factories
from test_api_workspaced_base import API_PREFIX, ReadOnlyAPITests
from server.models import (
    Command,
    Workspace,
)
from server.api.modules.commandsrun import CommandView
from server.api.modules.workspaces import WorkspaceView
from test_cases.factories import VulnerabilityFactory, EmptyCommandFactory, CommandObjectFactory


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
        vuln_id = command.command_objects[0].object_id
        session.flush()
        CommandObjectFactory.create(
            command=another_command,
            object_type='Vulnerability',
            object_id=vuln_id
        )
        session.commit()
        res = test_client.get(self.url(workspace=command.workspace) + 'activity_feed/')
        assert res.status_code == 200
        assert filter(lambda stats: stats['command'] == command.id, res.json)[0]['sum_created_vulnerabilities'] == 1
        assert filter(lambda stats: stats['command'] == another_command.id, res.json)[0]['sum_created_vulnerabilities'] == 0
