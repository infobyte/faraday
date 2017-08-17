import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import string
import random
import unittest

from server.dao.host import HostDAO
from test_cases.factories import WorkspaceFactory, HostFactory


def test_list_with_multiple_workspace(app, session):
    with app.app_context():
        workspace = WorkspaceFactory.build()

        hosts_dao = HostDAO(workspace)
        expected = {'rows': [], 'total_rows': 0}

        res = hosts_dao.list()
        assert expected == res

        host = HostFactory.build(workspace=workspace)
        session.add(host)
        session.commit()
        expected = {'rows': [{'value': {'description': host.description, 'default_gateway': [None, None], 'vulns': 0, '_rev': None, 'owned': None, 'owner': None, 'services': 0, 'credentials': 0, 'name': host.name, '_id': None, 'os': host.os, 'interfaces': [], 'metadata': {'update_time': None, 'create_time': None, 'update_user': None, 'update_action': None, 'creator': None, 'owner': None, 'update_controller_action': None, 'command_id': None}}, '_id': host.id, 'id': None, 'key': None}], 'total_rows': 1}
        res = hosts_dao.list()
        assert expected == res

        another_workspace = WorkspaceFactory.build()

        another_host = HostFactory.build(workspace=another_workspace)
        session.add(another_host)
        session.commit()

        res = hosts_dao.list()
        assert expected == res


def test_count_with_multiple_workspace(app, session):
    with app.app_context():
        workspace = WorkspaceFactory.build()

        hosts_dao = HostDAO(workspace)
        expected = {'total_count': 0}

        res = hosts_dao.count()
        assert expected == res

        host = HostFactory.build(workspace=workspace)
        session.add(host)
        session.commit()

        another_workspace = WorkspaceFactory.build()

        another_host = HostFactory.build(workspace=another_workspace)
        session.add(another_host)
        session.commit()

        expected = {'total_count': 1}

        res = hosts_dao.count()
        assert expected == res
