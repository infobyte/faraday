import pytest
from sqlalchemy.orm.util import was_deleted
from test_cases import factories
from server.models import db, Workspace, Host

PREFIX = '/v2/'
HOSTS_COUNT = 5

@pytest.mark.usefixtures('database', 'logged_user')
class TestHostAPI:

    @pytest.fixture(autouse=True)
    def load_workspace_with_hosts(self, database, session, workspace, host_factory):
        host_factory.create_batch(HOSTS_COUNT, workspace=workspace)
        session.commit()
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

    def test_list_retrieves_all_items_from_workspace(self, test_client,
                                                     second_workspace,
                                                     session,
                                                     host_factory):
        other_host = host_factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json) == HOSTS_COUNT

    def test_retrieve_one_host(self, test_client, database):
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

    def test_create_a_host_succeeds(self, test_client):
        res = test_client.post(self.url(), data={
            "ip": "127.0.0.1",
            "description": "aaaaa",
            # os is not required
        })
        assert res.status_code == 201
        assert Host.query.count() == HOSTS_COUNT + 1
        host_id = res.json['id']
        host = Host.query.get(host_id)
        assert host.ip == "127.0.0.1"
        assert host.description == "aaaaa"
        assert host.os is None
        assert host.workspace == self.workspace

    def test_create_a_host_fails_with_missing_desc(self, test_client):
        res = test_client.post(self.url(), data={
            "ip": "127.0.0.1",
        })
        assert res.status_code == 400

    def test_create_a_host_fails_with_existing_ip(self, session,
                                                  test_client, host):
        session.add(host)
        session.commit()

        res = test_client.post(self.url(), data={
            "ip": host.ip,
            "description": "aaaaa",
        })
        assert res.status_code == 400
        assert Host.query.count() == HOSTS_COUNT + 1

    def test_create_a_host_with_ip_of_other_workspace(self, test_client,
                                                      session,
                                                      second_workspace, host):
        session.add(host)
        session.commit()

        res = test_client.post(self.url(workspace=second_workspace), data={
            "ip": host.ip,
            "description": "aaaaa",
        })
        assert res.status_code == 201
        # It should create two hosts, one for each workspace
        assert Host.query.count() == HOSTS_COUNT + 2

    def test_update_a_host(self, test_client):
        host = self.workspace.hosts[0]
        res = test_client.put(self.url(host), data={
            "ip": host.ip,
            "description": "bbbbb",
        })
        assert res.status_code == 200
        assert res.json['description'] == 'bbbbb'
        assert Host.query.get(res.json['id']).description == 'bbbbb'
        assert Host.query.count() == HOSTS_COUNT

    def test_update_a_host_fails_with_existing_ip(self, test_client, session):
        host = self.workspace.hosts[0]
        original_ip = host.ip
        original_desc = host.description
        res = test_client.put(self.url(host), data={
            "ip": self.workspace.hosts[1].ip,  # Existing IP
            "description": "bbbbb",
        })
        assert res.status_code == 400
        session.refresh(host)
        assert host.ip == original_ip
        assert host.description == original_desc  # It shouldn't do a partial update

    def test_update_a_host_fails_with_missing_fields(self, test_client):
        """To do this the user should use a PATCH request"""
        host = self.workspace.hosts[0]
        res = test_client.put(self.url(host), data={
            "ip": "1.2.3.4",  # Existing IP
        })
        assert res.status_code == 400

    def test_delete_a_host(self, test_client):
        host = self.workspace.hosts[0]
        res = test_client.delete(self.url(host))
        assert res.status_code == 204  # No content
        assert was_deleted(host)

    def test_delete_host_from_other_workspace_fails(self, test_client,
                                                    second_workspace):
        host = self.workspace.hosts[0]
        res = test_client.delete(self.url(host, workspace=second_workspace))
        assert res.status_code == 404  # No content
        assert not was_deleted(host)
