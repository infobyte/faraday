import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import string
import random
import unittest
from server.web import app
from server.models import db, Service

from server.dao.service import ServiceDAO
from test_cases.factories import WorkspaceFactory, ServiceFactory


class VulnerabilityDAOTestCases(unittest.TestCase):

    def setUp(self):
        with app.app_context():
            db.create_all()
            self.workspace = WorkspaceFactory.build()
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.drop_all()

    def test_list_with_multiple_workspace(self):
        with app.app_context():
            workspace = WorkspaceFactory.build()
            service_dao = ServiceDAO(workspace)
            expected = {'services': []}

            res = service_dao.list()
            assert expected == res

            new_service = ServiceFactory.build(workspace=workspace)
            db.session.add(new_service)
            db.session.commit()

            res = service_dao.list()
            expected = {'services': [{'value': {'status': None, 'protocol': None, 'description': new_service.description, '_rev': None, 'owned': None, 'owner': None, 'credentials': 0, 'name': new_service.name, 'version': None, '_id': None, 'ports': [int(new_service.ports)], 'metadata': {'update_time': None, 'create_time': None, 'update_user': None, 'update_action': None, 'creator': None, 'owner': None, 'update_controller_action': None, 'command_id': None}}, '_id': 2, 'id': None, 'key': None, 'vulns': 0}]}

            assert expected == res

            another_workspace = WorkspaceFactory.build()
            another_service = ServiceFactory.build(workspace=another_workspace)
            db.session.add(another_service)
            db.session.commit()
            res = service_dao.list()
            assert len(res['services']) == 1
            assert expected == res

    def test_count_with_multiple_workspaces(self):
        with app.app_context():
            workspace = WorkspaceFactory.build()
            service_dao = ServiceDAO(workspace)
            expected = {'total_count': 0}
            res = service_dao.count()
            assert expected == res
            new_service = ServiceFactory.build(workspace=workspace)
            db.session.add(new_service)
            db.session.commit()
            res = service_dao.count()
            expected = {'total_count': 1}
            assert expected == res
            another_workspace = WorkspaceFactory.build()
            another_service = ServiceFactory.build(workspace=another_workspace)
            db.session.add(another_service)
            db.session.commit()
            res = service_dao.count()
            assert expected == res
