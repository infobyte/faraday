#-*- coding: utf8 -*-
"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest
from test_cases import factories
from test_api_workspaced_base import ListTestsMixin, API_PREFIX, GenericAPITest
from server.models import (
    Command,
    Workspace,
)
from server.api.modules.commandsrun import CommandView
from server.api.modules.workspaces import WorkspaceView


@pytest.mark.usefixtures('logged_user')
class TestListCommandView(GenericAPITest):
    model = Command
    factory = factories.CommandFactory
    api_endpoint = 'commands'
    unique_fields = ['ip']
    update_fields = ['ip', 'description', 'os']
    view_class = CommandView

    def test_(self, test_client, second_workspace, session):
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