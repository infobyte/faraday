import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import string
import random
import unittest
from server.web import app
from server.models import db, Vulnerability, Workspace

from server.dao.vuln import VulnerabilityDAO
from test_cases.factories import WorkspaceFactory, VulnerabilityFactory


class VulnerabilityDAOTestCases(unittest.TestCase):

    def setUp(self):
        with app.app_context():
            db.create_all()
            self.workspace = WorkspaceFactory.build()
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.drop_all()

    def test_vulnerability_count_per_workspace_is_filtered(self):
        """
            Verifies that the dao return the correct count from each workspace
        """
        with app.app_context():
            another_workspace = WorkspaceFactory.build()
            vuln_dao = VulnerabilityDAO(self.workspace)
            another_vuln_dao = VulnerabilityDAO(another_workspace)
            vuln_1 = VulnerabilityFactory.build(vuln_type='Vulnerability', workspace=self.workspace)
            vuln_2 = VulnerabilityFactory.build(vuln_type='Vulnerability', workspace=another_workspace)
            db.session.add(vuln_1)
            db.session.add(vuln_2)
            db.session.commit()
            ws_count = vuln_dao.count()
            another_ws_count = another_vuln_dao.count()
            ws_expected = {'total_count': 1, 'web_vuln_count': 0, 'vuln_count': 1}
            another_expected = {'total_count': 1, 'web_vuln_count': 0, 'vuln_count': 1}
            assert ws_count == ws_expected
            assert another_ws_count == another_expected

    def test_count_by_type(self):
        with app.app_context():
            vuln_dao = VulnerabilityDAO(self.workspace)
            res = vuln_dao.count()
            expected = {'total_count': 0, 'web_vuln_count': 0, 'vuln_count': 0}
            self.assertEquals(expected, res)
            vuln = VulnerabilityFactory.build(vuln_type='Vulnerability', workspace=self.workspace)
            vuln_web = VulnerabilityFactory.build(vuln_type='VulnerabilityWeb', workspace=self.workspace)
            db.session.add(vuln)
            db.session.add(vuln_web)
            db.session.commit()
            res = vuln_dao.count()
            expected = {'total_count': 2, 'web_vuln_count': 1, 'vuln_count': 1}
            assert expected == res
