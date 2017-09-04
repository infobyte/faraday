import pytest
from test_cases import factories
from server.models import db, Workspace

PREFIX = '/v2/'
HOSTS_COUNT = 5

@pytest.mark.usefixtures('database', 'logged_user')
class TestHostAPI:

    @pytest.fixture(autouse=True)
    def load_workspace_with_hosts(self, database, session, workspace, host_factory):
        host_factory.create_batch(HOSTS_COUNT, workspace=workspace)
        database.session.commit()
        assert workspace.id is not None
        assert workspace.hosts[0].id is not None
        self.workspace = workspace
        return workspace

    def url(self, host=None, workspace=None):
        workspace = workspace or self.workspace
        url = PREFIX + workspace.name + '/hosts/'
        if host is not None:
            url += str(host.id)
        return url

    def test_list_retrieves_all_items(self, test_client):
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json) == HOSTS_COUNT

    def test_retrieve_one_host(self, test_client, database):
        # self.workspace = Workspace.query.first()
        host = self.workspace.hosts[0]
        assert host.id is not None
        res = test_client.get(self.url(host))
        assert res.status_code == 200
        assert res.json['ip'] == host.ip

    def test_retrieve_fails_with_host_of_another_workspace(self,
                                                           test_client,
                                                           session,
                                                           workspace_factory):
        new = workspace_factory.create()
        session.commit()
        res = test_client.get(self.url(self.workspace.hosts[0], new))
        assert res.status_code == 404

