import pytest

from faraday.searcher.api import Api
from faraday.searcher.searcher import Searcher
from faraday.server.models import Vulnerability, CommandObject
from tests.factories import WorkspaceFactory, VulnerabilityFactory


def check_command(vuln, session):
    command_obj_rel = session.query(CommandObject).filter_by(object_type='vulnerability', object_id=vuln.id).first()
    assert command_obj_rel is not None
    assert command_obj_rel.command.tool == 'Searcher'
    count = session.query(CommandObject).filter_by(object_type='vulnerability', object_id=vuln.id).count()
    assert count == 1


@pytest.mark.usefixtures('logged_user')
class TestSearcherRules():
    def test_searcher_update_rules(self, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low')
        session.add(workspace)
        session.add(vuln)
        session.commit()
        api = Api(test_client, workspace.name, username='test', password='test', base='')
        searcher = Searcher(api)

        rules = [{
            'id': 'CHANGE_SEVERITY',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--UPDATE:severity=med"]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1
        vuln = session.query(Vulnerability).filter_by(workspace=workspace).first()
        assert vuln.severity == 'medium'
        check_command(vuln, session)

    def test_searcher_delete_rules(self, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low')
        session.add(workspace)
        session.add(vuln)
        session.commit()
        api = Api(test_client, workspace.name, username='test', password='test', base='')
        searcher = Searcher(api)

        rules = [{
            'id': 'DELETE_LOW',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--DELETE:"]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 0

    @pytest.mark.skip("No available in community")
    def test_searcher_rules_tag_vulns_low(self, session, test_client):
        workspace = WorkspaceFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, severity='low')
        session.add(workspace)
        session.add(vuln)
        session.commit()
        api = Api(test_client, workspace.name, username='test', password='test', base='')
        searcher = Searcher(api)

        rules = [{
            'id': 'DELETE_LOW',
            'model': 'Vulnerability',
            'object': "severity=low",
            'actions': ["--UPDATE:tags=TEST"]
        }]

        searcher.process(rules)
        vulns_count = session.query(Vulnerability).filter_by(workspace=workspace).count()
        assert vulns_count == 1
        vuln = session.query(Vulnerability).filter_by(workspace=workspace, id=vuln.id).first()
        assert list(vuln.tags) == ["TEST"]
        check_command(vuln, session)

