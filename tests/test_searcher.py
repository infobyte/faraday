import pytest

from faraday.searcher.api import Api
from faraday.searcher.searcher import Searcher
from tests.factories import WorkspaceFactory


@pytest.mark.usefixtures('logged_user')
class TestSearcherRules():

    def test_searcher_rules(self, session, test_client):
        workspace = WorkspaceFactory.create()
        session.add(workspace)
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