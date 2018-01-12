import time
import operator
try:
    import urlparse
    from urllib import urlencode
except: # For Python 3
    import urllib.parse as urlparse
    from urllib.parse import urlencode
from sqlalchemy.orm.util import was_deleted

import pytest

from test_cases import factories
from test_api_workspaced_base import (
    API_PREFIX,
    ReadWriteAPITests,
    PaginationTestsMixin,
)
from server.models import db, Host
from server.api.modules.hosts import HostsView
from test_cases.factories import HostFactory, CommandFactory, \
    EmptyCommandFactory, WorkspaceFactory

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
                count, host=host, workspace=host.workspace, status='open')
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

    def compare_results(self, hosts, response):
        """
        Compare is the hosts in response are the same that in hosts.
        It only compares the IDs of each one, not other fields"""
        hosts_in_list = set(host.id for host in hosts)
        hosts_in_response = set(host['id'] for host in response.json['rows'])
        assert hosts_in_list == hosts_in_response

    def test_list_retrieves_all_items_from_workspace(self, test_client,
                                                     second_workspace,
                                                     session,
                                                     host_factory):
        other_host = host_factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json['rows']) == HOSTS_COUNT

    def test_retrieve_one_host(self, test_client, database):
        host = self.workspace.hosts[0]
        assert host.id is not None
        res = test_client.get(self.url(host))
        assert res.status_code == 200
        assert res.json['name'] == host.ip

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
        assert res.status_code == 409
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
        assert res.status_code == 409
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

    def test_retrieve_shows_service_count(self, test_client, host_services,
                                          service_factory):
        for (host, services) in host_services.items():
            # Adding closed and filtered services shouldn't impact on the
            # service count since it should only count opened services
            service_factory.create_batch(3, status='closed', host=host,
                                         workspace=host.workspace)
            service_factory.create_batch(2, status='filtered', host=host,
                                         workspace=host.workspace)
            res = test_client.get(self.url(host))
            assert res.json['services'] == len(services)

    def test_index_shows_service_count(self, test_client, host_services,
                                       service_factory):
        ids_map = {host.id: services
                   for (host, services) in host_services.items()}

        # Adding closed and filtered services shouldn't impact on the
        # service count since it should only count opened services
        for host in host_services.keys():
            service_factory.create_batch(3, status='closed', host=host,
                                         workspace=host.workspace)
            service_factory.create_batch(2, status='filtered', host=host,
                                         workspace=host.workspace)

        res = test_client.get(self.url())
        assert len(res.json['rows']) >= len(ids_map)  # Some hosts can have no services
        for host in res.json['rows']:
            if host['id'] in ids_map:
                assert host['value']['services'] == len(ids_map[host['id']])

    def test_filter_by_os_exact(self, test_client, session, workspace,
                                second_workspace, host_factory):
        # The hosts that should be shown
        hosts = host_factory.create_batch(10, workspace=workspace, os='Unix')

        # Search should be case sensitive so this shouln't be shown
        host_factory.create_batch(1, workspace=workspace, os='UNIX')

        # This shouldn't be shown, they are from other workspace
        host_factory.create_batch(5, workspace=second_workspace, os='Unix')

        url = self.url() + '?os=Unix'
        res = test_client.get(url)
        assert res.status_code == 200
        self.compare_results(hosts, res)

    def test_filter_by_os_like_ilike(self, test_client, session, workspace,
                                     second_workspace, host_factory):
        # The hosts that should be shown
        hosts = host_factory.create_batch(5, workspace=workspace, os='Unix 1')
        hosts += host_factory.create_batch(5, workspace=workspace, os='Unix 2')

        # This should only be shown when using ilike, not when using like
        case_insensitive_host = host_factory.create(
            workspace=workspace, os='UNIX 3')

        # This doesn't match the like expression
        host_factory.create(workspace=workspace, os="Test Unix 1")

        # This shouldn't be shown anywhere, they are from other workspace
        host_factory.create_batch(5, workspace=second_workspace, os='Unix')

        res = test_client.get(self.url() + '?os__like=Unix %')
        assert res.status_code == 200
        self.compare_results(hosts, res)

        res = test_client.get(self.url() + '?os__ilike=Unix %')
        assert res.status_code == 200
        self.compare_results(hosts + [case_insensitive_host], res)

    def test_filter_by_service(self, test_client, session, workspace,
                               service_factory, host_factory):
        services = service_factory.create_batch(10, workspace=workspace,
                                                name="IRC")
        hosts = [service.host for service in services]

        # Hosts that shouldn't be shown
        host_factory.create_batch(5, workspace=workspace)

        res = test_client.get(self.url() + '?service=IRC')
        assert res.status_code == 200
        shown_hosts_ids = set(obj['id'] for obj in res.json['rows'])
        expected_host_ids = set(host.id for host in hosts)
        assert shown_hosts_ids == expected_host_ids

    def test_search_ip(self, test_client, session, workspace, host_factory):
        host = host_factory.create(ip="longname",
                                   workspace=workspace)
        session.commit()
        res = test_client.get(self.url() + '?search=ONGNAM')
        assert res.status_code == 200
        assert len(res.json['rows']) == 1
        assert res.json['rows'][0]['id'] == host.id

    @pytest.mark.usefixtures('host_services')
    def test_search_service_name(self, test_client, session, workspace,
                                 service_factory):
        expected_hosts = [self.hosts[2], self.hosts[4]]
        for host in expected_hosts:
            service_factory.create(host=host, name="GOPHER 5",
                                   workspace=workspace)
        session.commit()
        res = test_client.get(self.url() + '?search=gopher')
        assert res.status_code == 200
        shown_hosts_ids = set(obj['id'] for obj in res.json['rows'])
        expected_host_ids = set(host.id for host in expected_hosts)
        assert shown_hosts_ids == expected_host_ids

    @pytest.mark.usefixtures('host_with_hostnames')
    def test_search_by_hostname(self, test_client, session, workspace):
        expected_hosts = [self.hosts[2], self.hosts[4]]
        for host in expected_hosts:
            host.set_hostnames(['staging.twitter.com'])
        session.commit()
        res = test_client.get(self.url() + '?search=twitter')
        assert res.status_code == 200
        shown_hosts_ids = set(obj['id'] for obj in res.json['rows'])
        expected_host_ids = set(host.id for host in expected_hosts)
        assert shown_hosts_ids == expected_host_ids

    def test_host_with_open_vuln_count_verification(self, test_client, session,
                                                    workspace, host_factory,
                                                    vulnerability_factory,
                                                    service_factory):

        host = host_factory.create(workspace=workspace)
        service = service_factory.create(host=host, workspace=workspace)
        vulnerability_factory.create(service=service, host=None, workspace=workspace)
        vulnerability_factory.create(service=None, host=host, workspace=workspace)

        session.commit()

        res = test_client.get(self.url())
        assert res.status_code == 200
        json_host = filter(lambda json_host: json_host['value']['id'] == host.id, res.json['rows'])[0]
        # the host has one vuln associated. another one via service.
        assert json_host['value']['vulns'] == 2

    def test_host_services_vuln_count_verification(self, test_client, session,
                                                   workspace, host_factory, vulnerability_factory,
                                                   service_factory):
        host = host_factory.create(workspace=workspace)
        service = service_factory.create(host=host, workspace=workspace)
        vulnerability_factory.create(service=service, host=None, workspace=workspace)
        session.commit()

        res = test_client.get(self.url() + str(host.id) + "/" + 'services/')
        assert res.status_code == 200
        assert res.json[0]['vulns'] == 1

    def test_create_host_with_hostnames(self, test_client):
        raw_data = {
            "ip": "192.168.0.21",
            "hostnames": ["google.com"],
            "mac": "00:00:00:00:00:00",
            "description": "",
            "os": "",
            "owned": False,
            "owner": ""
        }
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert res.json['hostnames'] == ['google.com']
        host = Host.query.get(res.json['id'])
        assert len(host.hostnames) == 1
        assert host.hostnames[0].name == 'google.com'

    def test_update_host_with_hostnames(self, test_client, session,
                                        host_with_hostnames):
        session.commit()
        data = {
            "ip": "192.168.0.21",
            "hostnames": ["other.com", "test.com"],
            "mac": "00:00:00:00:00:00",
            "description": "",
            "os": "",
            "owned": False,
            "owner": ""
        }
        res = test_client.put(self.url(host_with_hostnames), data=data)
        assert res.status_code == 200
        expected = set(["other.com", "test.com"])
        assert set(res.json['hostnames']) == expected
        assert set(hn.name for hn in host_with_hostnames.hostnames) == expected

    def test_create_host_with_default_gateway(self, test_client):
        raw_data = {
            "ip": "192.168.0.21",
            "default_gateway": "192.168.0.1",
            "mac": "00:00:00:00:00:00", "description": "",
            "os": "", "owned": False, "owner": ""
        }
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert res.json['default_gateway'] == '192.168.0.1'

    def test_update_host(self, test_client, session):
        host = HostFactory.create()
        session.commit()
        raw_data = {
            "metadata":
                        {
                            "update_time":1510688312.431,
                            "update_user":"UI Web",
                            "update_action":0,
                            "creator":"",
                            "create_time":1510673388000,
                            "update_controller_action":"",
                            "owner":"leonardo",
                            "command_id": None},
            "name":"10.31.112.21",
            "ip":"10.31.112.21",
            "_rev":"",
            "description":"",
            "default_gateway": None,
            "owned": False,
            "services":12,
            "hostnames":[],
            "vulns":43,
            "owner":"leonardo",
            "credentials":0,
            "_id": 4000,
            "os":"Microsoft Windows Server 2008 R2 Standard Service Pack 1",
            "id": 4000,
            "icon":"windows"}

        res = test_client.put(self.url(host, workspace=host.workspace), data=raw_data)
        assert res.status_code == 200
        updated_host = Host.query.filter_by(id=host.id).first()
        assert res.json == {
            u'_id': host.id,
            u'type': 'Host',
            u'_rev': u'',
            u'credentials': 0,
            u'default_gateway': None,
            u'description': u'',
            u'hostnames': [],
            u'id': host.id,
            u'ip': u'10.31.112.21',
            u'mac': None,
            u'metadata': {
                u'command_id': None,
                u'create_time': int(time.mktime(updated_host.create_date.timetuple())) * 1000,
                u'creator': u'',
                u'owner': host.creator.username,
                u'update_action': 0,
                u'update_controller_action': u'',
                u'update_time': int(time.mktime(updated_host.update_date.timetuple())) * 1000,
                u'update_user': u''},
            u'name': u'10.31.112.21',
            u'os': u'Microsoft Windows Server 2008 R2 Standard Service Pack 1',
            u'owned': False,
            u'owner': host.creator.username,
            u'services': 0,
            u'vulns': 0}



class TestHostAPIGeneric(ReadWriteAPITests, PaginationTestsMixin):
    model = Host
    factory = factories.HostFactory
    api_endpoint = 'hosts'
    unique_fields = ['ip']
    update_fields = ['ip', 'description', 'os']
    view_class = HostsView

    @pytest.mark.usefixtures("mock_envelope_list")
    def test_sort_by_description(self, test_client, session):
        for host in Host.query.all():
            # I don't want to test case sensitive sorting
            host.description = host.description.lower()
        session.commit()
        expected_ids = [host.id for host in
                        sorted(Host.query.all(),
                               key=operator.attrgetter('description'))]
        res = test_client.get(self.url() + '?sort=description&sort_dir=asc')
        assert res.status_code == 200
        assert [host['_id'] for host in res.json['data']] == expected_ids

        expected_ids.reverse()  # In place list reverse
        res = test_client.get(self.url() + '?sort=description&sort_dir=desc')
        assert res.status_code == 200
        assert [host['_id'] for host in res.json['data']] == expected_ids

    @pytest.mark.usefixtures("mock_envelope_list")
    def test_sort_by_services(self, test_client, session, second_workspace,
                              host_factory, service_factory):
        expected_ids = []
        for i in range(10):
            host = host_factory.create(workspace=second_workspace)
            service_factory.create_batch(
                i, host=host, workspace=second_workspace, status='open')
            session.flush()
            expected_ids.append(host.id)
        session.commit()
        res = test_client.get(self.url(workspace=second_workspace) +
                              '?sort=services&sort_dir=asc')
        assert res.status_code == 200
        assert [h['_id'] for h in res.json['data']] == expected_ids

    @pytest.mark.usefixtures("mock_envelope_list")
    def test_sort_by_update_time(self, test_client, session, second_workspace,
                                 host_factory):
        """
        This test doesn't test only the hosts view, but all the ones that
        expose a object with metadata.
        Think twice if you are thinking in removing it
        """
        expected = host_factory.create_batch(10, workspace=second_workspace)
        session.commit()
        for i in range(len(expected)):
            if i % 2 == 0:   # Only update some hosts
                host = expected.pop(0)
                host.description = 'i was updated'
                session.add(host)
                session.commit()
                expected.append(host)  # Put it on the end
        res = test_client.get(self.url(workspace=second_workspace) +
                              '?sort=metadata.update_time&sort_dir=asc')
        assert res.status_code == 200, res.data
        assert [h['_id'] for h in res.json['data']] == [h.id for h in expected]

    def test_create_a_host_twice_returns_conflict(self, test_client):
        res = test_client.post(self.url(), data={
            "ip": "127.0.0.1",
            "description": "aaaaa",
        })
        assert res.status_code == 201
        assert Host.query.count() == HOSTS_COUNT + 1
        host_id = res.json['id']
        host = Host.query.get(host_id)
        assert host.ip == "127.0.0.1"
        assert host.description == "aaaaa"
        assert host.os is None
        assert host.workspace == self.workspace
        res = test_client.post(self.url(), data={
            "ip": "127.0.0.1",
            "description": "aaaaa",
        })
        assert res.status_code == 409
        assert res.json['object']['_id'] == host_id

    def test_create_host_from_command(self, test_client, session):
        command = EmptyCommandFactory.create()
        session.commit()
        assert len(command.command_objects) == 0
        url = self.url(workspace=command.workspace) + '?' + urlencode({'command_id': command.id})

        res = test_client.post(url, data={
            "ip": "127.0.0.1",
            "description": "aaaaa",
        })

        assert res.status_code == 201
        assert len(command.command_objects) == 1
        cmd_obj = command.command_objects[0]
        assert cmd_obj.object_type == 'Host'
        assert cmd_obj.object_id == res.json['id']

    def test_create_host_cant_assign_command_from_another_workspace(self, test_client, session):
        command = EmptyCommandFactory.create()
        new_workspace = WorkspaceFactory.create()
        session.commit()
        assert len(command.command_objects) == 0
        url = self.url(workspace=new_workspace) + '?' + urlencode({'command_id': command.id})

        res = test_client.post(url, data={
            "ip": "127.0.0.1",
            "description": "aaaaa",
        })

        assert res.status_code == 400
        assert res.json == {u'message': u'Command not found.'}
        assert len(command.command_objects) == 0
