import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import string
import random
import unittest

from server.dao.command import CommandDAO
from test_cases.factories import WorkspaceFactory, CommandFactory


def test_list_with_multiple_workspace(app, session):
    with app.app_context():
        workspace = WorkspaceFactory.build()

        commands_dao = CommandDAO(workspace)
        expected = {'commands': []}

        res = commands_dao.list()
        assert expected == res

        command = CommandFactory.build(workspace=workspace)
        session.add(command)
        session.commit()
        expected = {'commands': [{'value': {'itime': None, 'command': command.command, 'user': None, 'workspace': 0, 'params': None, 'duration': None, 'ip': None, '_id': None, 'hostname': None}, 'id': None, 'key': None}]}
        res = commands_dao.list()
        assert expected == res

        another_workspace = WorkspaceFactory.build()

        another_command = CommandFactory.build(workspace=another_workspace)
        session.add(another_command)
        session.commit()

        res = commands_dao.list()
        assert len(res['commands']) == 1
        assert expected == res
