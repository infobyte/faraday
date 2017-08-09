import string
import random
import unittest
from server.models import Vulnerability
from server.database import Workspace

from server.database import initialize, get_manager
from server.dao.vuln import VulnerabilityDAO

initialize()


class VulnerabilityDAOTestCases(unittest.TestCase):

    def setUp(self):
        self.manager = get_manager()
        self.workspace_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(15))

        self.manager.create_workspace({'name': self.workspace_name})

    def tearDown(self):
        self.manager.delete_workspace({'name': self.workspace_name})

    def _new_vuln(self, vuln_type):
        new_vuln = Vulnerability()
        new_vuln.name = 'Test vuln'
        new_vuln.description = 'Test description'
        new_vuln.vuln_type = vuln_type
        self.manager.get_workspace(self.workspace_name).session.add(new_vuln)
        self.manager.get_workspace(self.workspace_name).session.commit()
        return new_vuln

    def test_count(self):
        vuln_dao = VulnerabilityDAO(self.workspace_name)
        res = vuln_dao.count()
        expected = {'total_count': 0, 'web_vuln_count': 0, 'vuln_count': 0}
        self.assertEquals(expected, res)
        self._new_vuln('Vulnerability')
        self._new_vuln('VulnerabilityWeb')
        res = vuln_dao.count()
        expected = {'total_count': 2, 'web_vuln_count': 1, 'vuln_count': 1}
        self.assertEquals(expected, res)
