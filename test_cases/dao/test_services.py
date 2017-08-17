import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import string
import random
import unittest

from server.dao.service import ServiceDAO
from test_cases.factories import WorkspaceFactory, ServiceFactory


def test_list_with_multiple_workspace(app, session):
    with app.app_context():
        workspace = WorkspaceFactory.build()
        service_dao = ServiceDAO(workspace)
        expected = {'services': []}

        res = service_dao.list()
        assert expected == res

        new_service = ServiceFactory.build(workspace=workspace)
        session.add(new_service)
        session.commit()

        res = service_dao.list()
        expected = {'services': [{'value': {'status': None, 'protocol': None, 'description': new_service.description, '_rev': None, 'owned': None, 'owner': None, 'credentials': 0, 'name': new_service.name, 'version': None, '_id': None, 'ports': [int(new_service.ports)], 'metadata': {'update_time': None, 'create_time': None, 'update_user': None, 'update_action': None, 'creator': None, 'owner': None, 'update_controller_action': None, 'command_id': None}}, '_id': new_service.id, 'id': None, 'key': None, 'vulns': 0}]}

        assert expected == res

        another_workspace = WorkspaceFactory.build()
        another_service = ServiceFactory.build(workspace=another_workspace)
        session.add(another_service)
        session.commit()
        res = service_dao.list()
        assert len(res['services']) == 1
        assert expected == res


def test_count_with_multiple_workspaces(app, session):
    with app.app_context():
        workspace = WorkspaceFactory.build()
        service_dao = ServiceDAO(workspace)
        expected = {'total_count': 0}
        res = service_dao.count()
        assert expected == res
        new_service = ServiceFactory.build(workspace=workspace)
        session.add(new_service)
        session.commit()
        res = service_dao.count()
        expected = {'total_count': 1}
        assert expected == res
        another_workspace = WorkspaceFactory.build()
        another_service = ServiceFactory.build(workspace=another_workspace)
        session.add(another_service)
        session.commit()
        res = service_dao.count()
        assert expected == res
