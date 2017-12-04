import pytest

from server.models import Workspace
from server.api.modules.workspaces import WorkspaceView
from test_cases.test_api_non_workspaced_base import ReadWriteAPITests, API_PREFIX
from test_cases import factories

class TestWorkspaceAPI(ReadWriteAPITests):
    model = Workspace
    factory = factories.WorkspaceFactory
    api_endpoint = 'ws'
    lookup_field = 'name'
    view_class = WorkspaceView

    def test_host_count(self, host_factory, test_client, session):
        host_factory.create(workspace=self.first_object)
        session.commit()
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        assert res.json['stats']['hosts'] == 1

    @pytest.mark.parametrize('querystring', [
        '',
        '?confirmed=0',
        '?confirmed=false'
    ])

    def test_vuln_count(self, vulnerability_factory, test_client, session,
                        querystring):
        vulnerability_factory.create_batch(8, workspace=self.first_object,
                                           confirmed=False)
        vulnerability_factory.create_batch(5, workspace=self.first_object,
                                           confirmed=True)
        session.commit()
        res = test_client.get(self.url(self.first_object) + querystring)
        assert res.status_code == 200
        assert res.json['stats']['total_vulns'] == 13

    @pytest.mark.parametrize('querystring', [
        '?confirmed=1',
        '?confirmed=true'
    ])

    def test_vuln_count_confirmed(self, vulnerability_factory, test_client,
                                  session, querystring):
        vulnerability_factory.create_batch(8, workspace=self.first_object,
                                           confirmed=False)
        vulnerability_factory.create_batch(5, workspace=self.first_object,
                                           confirmed=True)
        session.commit()
        res = test_client.get(self.url(self.first_object) + querystring)
        assert res.status_code == 200
        assert res.json['stats']['total_vulns'] == 5