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


def test_vulnerability_count_and_list_per_workspace_is_filtered(app, session):
    """
        Verifies that the dao return the correct count from each workspace
    """
    with app.app_context():
        workspace = WorkspaceFactory.build()
        another_workspace = WorkspaceFactory.build()
        vuln_dao = VulnerabilityDAO(workspace)
        another_vuln_dao = VulnerabilityDAO(another_workspace)
        vuln_1 = VulnerabilityFactory.build(vuln_type='Vulnerability', workspace=workspace)
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
        ws_list = vuln_dao.list()

        assert vuln_1.id == ws_list['vulnerabilities'][0]['_id']
        another_ws_list = another_vuln_dao.list()
        assert vuln_2.id == another_ws_list['vulnerabilities'][0]['_id']


def test_count_by_type(app, session):
    with app.app_context():
        workspace = WorkspaceFactory.build()
        vuln_dao = VulnerabilityDAO(workspace)
        res = vuln_dao.count()
        expected = {'total_count': 0, 'web_vuln_count': 0, 'vuln_count': 0}
        assert expected == res
        vuln = VulnerabilityFactory.build(vuln_type='Vulnerability', workspace=workspace)
        vuln_web = VulnerabilityFactory.build(vuln_type='VulnerabilityWeb', workspace=workspace)
        db.session.add(vuln)
        db.session.add(vuln_web)
        db.session.commit()
        res = vuln_dao.count()
        expected = {'total_count': 2, 'web_vuln_count': 1, 'vuln_count': 1}
        assert expected == res
