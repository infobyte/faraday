import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import string
import random
import unittest
from server.web import app
from server.models import Vulnerability, Workspace

from server.dao.vuln import VulnerabilityDAO
from test_cases.factories import WorkspaceFactory, VulnerabilityFactory


class VulnerabilityDAOTestCases(unittest.TestCase):

    def setUp(self):
        self.workspace_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(15))
        self.workspace = WorkspaceFactory.build()

    def _new_vuln(self, vuln_type):
        new_vuln = VulnerabilityFactory.build()
        new_vuln.name = 'Test vuln'
        new_vuln.description = 'Test description'
        new_vuln.vuln_type = vuln_type
        return new_vuln

    def test_count(self):
        with app.app_context():
            vuln_dao = VulnerabilityDAO(self.workspace_name)
            res = vuln_dao.count()
            expected = {'total_count': 0, 'web_vuln_count': 0, 'vuln_count': 0}
            self.assertEquals(expected, res)
            self._new_vuln('Vulnerability')
            self._new_vuln('VulnerabilityWeb')
            res = vuln_dao.count()
            expected = {'total_count': 2, 'web_vuln_count': 1, 'vuln_count': 1}
            self.assertEquals(expected, res)
