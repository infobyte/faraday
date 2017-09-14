import pytest
from sqlalchemy.orm.util import was_deleted

from test_cases import factories
from test_api_workspaced_base import (
    API_PREFIX,
    ReadWriteAPITests,
    PaginationTestsMixin,
)
from server.models import db, Host
from server.api.modules.hosts import HostsView

HOSTS_COUNT = 5
SERVICE_COUNT = [10, 5]  # 10 services to the first host, 5 to the second

@pytest.mark.usefixtures('database', 'logged_user')
class TestHostAPI:

    @pytest.fixture(autouse=True)
    def load_workspace_with_hosts(self, database, session, workspace, host_factory):
        self.hosts = host_factory.create_batch(HOSTS_COUNT,
                                               workspace=workspace)
        self.first_host = self.hosts[0]
        session.commit()
        assert workspace.id is not None
        assert workspace.hosts[0].id is not None
        self.workspace = workspace
        return workspace

    @pytest.fixture
    def host_services(self, session, service_factory):
        """
        Add some services to the first len(SERVICE_COUNT) hosts.

        Return a dictionary mapping hosts to a list of services
        """
        ret = {}
        for (count, host) in zip(SERVICE_COUNT, self.hosts):
            ret[host] = service_factory.create_batch(
                count, host=host, workspace=host.workspace)
        session.commit()
        return ret

    def url(self, host=None, workspace=None):
        workspace = workspace or self.workspace
        url = API_PREFIX + workspace.name + '/hosts/'
        if host is not None:
            url += str(host.id) + '/'
        return url

    def services_url(self, host, workspace=None):
        return self.url(host, workspace) + 'services/'

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

    def test_get_host_services(self, test_client, session,
                               service_factory):
        # Create the services that must be shown
        real = service_factory.create_batch(
            SERVICE_COUNT[0],
            host=self.first_host,
            workspace=self.first_host.workspace)

        # Create a service of other host, must not be shown
        other_host = service_factory.create(
            host=self.hosts[1],
            workspace=self.hosts[1].workspace)

        session.commit()
        ids_expected = {host.id for host in real}

        res = test_client.get(self.services_url(self.first_host))
        assert res.status_code == 200
        ids_returned = {host['id'] for host in res.json}
        assert other_host.id not in ids_returned
        assert ids_expected == ids_returned

    def test_retrieve_shows_service_count(self, test_client, host_services):
        for (host, services) in host_services.items():
            res = test_client.get(self.url(host))
            assert res.json['service_count'] == len(services)

    def test_index_shows_service_count(self, test_client, host_services):
        ids_map = {host.id: services
                   for (host, services) in host_services.items()}
        res = test_client.get(self.url())
        assert len(res.json) >= len(ids_map)  # Some hosts can have no services
        for host in res.json:
            if host['id'] in ids_map:
                assert host['service_count'] == len(ids_map[host['id']])


class TestHostAPIGeneric(ReadWriteAPITests, PaginationTestsMixin):
    model = Host
    factory = factories.HostFactory
    api_endpoint = 'hosts'
    unique_fields = ['ip']
    update_fields = ['ip', 'description', 'os']
    view_class = HostsView

