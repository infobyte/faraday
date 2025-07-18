'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import operator
from io import BytesIO
from posixpath import join

from urllib.parse import urljoin
from random import choice
from hypothesis import given, strategies as st

import pytest

from tests import factories
from tests.test_api_workspaced_base import PaginationTestsMixin
from tests.test_api_non_workspaced_base import (
    API_PREFIX,
    ReadOnlyAPITests,
    BulkUpdateTestsMixin,
    BulkDeleteTestsMixin
)
from faraday.server.models import db, Host
from faraday.server.api.modules.hosts_base import HostView
from faraday.server.tasks import calc_vulnerability_stats
from tests.factories import (
    HostFactory,
    WorkspaceFactory,
    HostnameFactory,
    VulnerabilityFactory,
)

HOSTS_COUNT = 5
SERVICE_COUNT = [10, 5]  # 10 services to the first host, 5 to the second


@pytest.mark.usefixtures('database', 'logged_user')
@pytest.mark.skip_sql_dialect('sqlite')
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

    @staticmethod
    def url(host=None):
        url = join(API_PREFIX, 'hosts')
        if host is not None:
            url = join(url, str(host.id))
        return url

    def services_url(self, host):
        return join(self.url(host), 'services')

    def compare_results(self, hosts, response):
        """
        Compare is the hosts in response are the same that in hosts.
        It only compares the IDs of each one, not other fields"""
        hosts_in_list = {host.id for host in hosts}
        hosts_in_response = {host['id'] for host in response.json['rows']}
        assert hosts_in_list == hosts_in_response

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_list_retrieves_all_items_from_all_workspace(self, test_client,
                                                     second_workspace,
                                                     session,
                                                     host_factory):
        host_factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200
        assert len(res.json['rows']) == HOSTS_COUNT + 1

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_list_retrieves_all_items_from_only_active_workspace(self, test_client,
                                                     second_workspace,
                                                     session,
                                                     host_factory):
        host_factory.create(workspace=second_workspace)
        session.commit()
        res = test_client.get(f"{self.url()}/filter")
        assert res.status_code == 200
        assert len(res.json['rows']) == HOSTS_COUNT + 1

        second_workspace.active = False
        session.commit()

        res = test_client.get(f"{self.url()}/filter")
        assert res.status_code == 200
        assert len(res.json['rows']) == HOSTS_COUNT

    def test_retrieve_one_host(self, test_client, database):
        host = self.workspace.hosts[0]
        assert host.id is not None
        res = test_client.get(self.url(host))
        assert res.status_code == 200
        assert res.json['name'] == host.ip

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

    def test_retrieve_shows_service_count(self, test_client, session,
                                          host_services, service_factory):
        for (host, services) in host_services.items():
            # Adding closed and filtered services shouldn't impact on the
            # service count since it should only count opened services
            service_factory.create_batch(3, status='closed', host=host,
                                         workspace=host.workspace)
            service_factory.create_batch(2, status='filtered', host=host,
                                         workspace=host.workspace)
            session.commit()
            res = test_client.get(self.url(host))
            assert res.json['services'] == len(services)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_index_shows_service_count(self, test_client, session,
                                       host_services, service_factory):
        ids_map = {host.id: services
                   for (host, services) in host_services.items()}

        # Adding closed and filtered services shouldn't impact on the
        # service count since it should only count opened services
        for host in host_services.keys():
            service_factory.create_batch(3, status='closed', host=host,
                                         workspace=host.workspace)
            service_factory.create_batch(2, status='filtered', host=host,
                                         workspace=host.workspace)

        session.commit()
        res = test_client.get(self.url())
        assert len(res.json['rows']) >= len(ids_map)  # Some hosts can have no services
        for host in res.json['rows']:
            if host['id'] in ids_map:
                assert host['value']['services'] == len(ids_map[host['id']])

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_by_os_exact(self, test_client, session, workspace,
                                second_workspace, host_factory):
        # The hosts that should be shown
        hosts = host_factory.create_batch(10, workspace=workspace, os='Unix')

        # Search should be case-sensitive so this shouldn't be shown
        host_factory.create_batch(1, workspace=workspace, os='UNIX')

        # This shouldn't be shown, they are from other workspace
        hosts += host_factory.create_batch(5, workspace=second_workspace, os='Unix')

        session.commit()
        url = urljoin(self.url(), '?os=Unix')
        res = test_client.get(url)
        assert res.status_code == 200
        self.compare_results(hosts, res)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_by_os_exact(self, test_client, session, workspace,
                                         second_workspace, host_factory):
        # The hosts that should be shown
        hosts = host_factory.create_batch(10, workspace=workspace, os='Unix')
        hosts_2 = host_factory.create_batch(5, workspace=second_workspace, os='Unix')

        # Search should be case-sensitive so this shouldn't be shown
        host_factory.create_batch(1, workspace=workspace, os='UNIX')

        session.commit()
        res = test_client.get(join(self.url(), 'filter?q={'
                                               '"filters":[{"name": "os", "op":"eq", "val":"Unix"}], '
                                               '"order_by": ['
                                               '{'
                                               '"field": "vulnerability_critical_generic_count", '
                                               '"direction": "desc"'
                                               '}'
                                               '] '
                                               '}'))

        assert res.status_code == 200
        self.compare_results(hosts + hosts_2, res)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_count(self, test_client, session, workspace,
                                   second_workspace, host_factory):
        # The hosts that should be shown
        hosts = host_factory.create_batch(30, workspace=workspace, os='Unix')

        # This should be shown, they are from other workspace
        host_factory.create_batch(5, workspace=second_workspace, os='Unix')

        session.commit()
        res = test_client.get(join(self.url(), 'filter?q={"filters":[{"name": "os", "op":"eq", "val":"Unix"}],'
                                                  '"offset":0, "limit":20}'))
        assert res.status_code == 200
        assert res.json['count'] == 35

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_filter_and_group_by_os(self, test_client, session, workspace, host_factory):
        host_factory.create_batch(10, workspace=workspace, os='Unix')
        host_factory.create_batch(1, workspace=workspace, os='unix')
        session.commit()
        res = test_client.get(join(self.url(), 'filter?q={"filters":[{"name": "os", "op": "like", "val": "%nix"}], '
                                                  '"group_by":[{"field": "os"}], "order_by":[{"field": "os", "direction": "desc"}]}'))
        assert res.status_code == 200
        assert len(res.json['rows']) == 2
        assert res.json['count'] == 2
        assert 'unix' in [row['value']['os'] for row in res.json['rows']]
        assert 'Unix' in [row['value']['os'] for row in res.json['rows']]

    @pytest.mark.usefixtures('ignore_nplusone')
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

        session.commit()
        res = test_client.get(urljoin(self.url(), '?os__like=Unix %'))
        assert res.status_code == 200
        self.compare_results(hosts, res)

        res = test_client.get(urljoin(self.url(), '?os__ilike=Unix %'))
        assert res.status_code == 200
        self.compare_results(hosts + [case_insensitive_host], res)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_by_os_like_ilike(self, test_client, session, workspace,
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

        session.commit()
        res = test_client.get(join(
            self.url(),
            'filter?q={"filters":[{"name": "os", "op":"like", "val":"Unix %"}]}'
        )
        )
        assert res.status_code == 200
        self.compare_results(hosts, res)

        res = test_client.get(join(
            self.url(),
            'filter?q={"filters":[{"name": "os", "op":"ilike", "val":"Unix %"}]}'
        )
        )
        assert res.status_code == 200
        self.compare_results(hosts + [case_insensitive_host], res)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_by_service(self, test_client, session, workspace,
                               service_factory, host_factory):
        services = service_factory.create_batch(10, workspace=workspace,
                                                name="IRC")
        hosts = [service.host for service in services]

        # Hosts that shouldn't be shown
        host_factory.create_batch(5, workspace=workspace)

        session.commit()
        res = test_client.get(urljoin(self.url(), '?service=IRC'))
        assert res.status_code == 200
        shown_hosts_ids = {obj['id'] for obj in res.json['rows']}
        expected_host_ids = {host.id for host in hosts}
        assert shown_hosts_ids == expected_host_ids

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_by_service_name(self, test_client, session, workspace,
                                             service_factory, host_factory):
        services = service_factory.create_batch(10, workspace=workspace,
                                                name="IRC")
        hosts = [service.host for service in services]

        # Hosts that shouldn't be shown
        host_factory.create_batch(5, workspace=workspace)

        session.commit()

        res = test_client.get(
            join(
                self.url(),
                'filter?q={"filters":[{"name": "services__name", "op":"any", "val":"IRC"}]}'
            )
        )
        assert res.status_code == 200
        shown_hosts_ids = {obj['id'] for obj in res.json['rows']}
        expected_host_ids = {host.id for host in hosts}
        assert shown_hosts_ids == expected_host_ids

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_by_service_port(self, test_client, session, workspace,
                                    service_factory, host_factory):
        services = service_factory.create_batch(10, workspace=workspace, port=25)
        hosts = [service.host for service in services]

        # Hosts that shouldn't be shown
        host_factory.create_batch(5, workspace=workspace)

        session.commit()
        res = test_client.get(urljoin(self.url(), '?port=25'))
        assert res.status_code == 200
        shown_hosts_ids = {obj['id'] for obj in res.json['rows']}
        expected_host_ids = {host.id for host in hosts}
        assert shown_hosts_ids == expected_host_ids

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_by_service_port(self, test_client, session, workspace,
                                             service_factory, host_factory):
        services = service_factory.create_batch(10, workspace=workspace, port=25)
        hosts = [service.host for service in services]

        # Hosts that shouldn't be shown
        host_factory.create_batch(5, workspace=workspace)

        session.commit()
        res = test_client.get(
            join(
                self.url(),
                'filter?q={"filters":[{"name": "services__port", "op":"any", "val":"25"}]}'
            )
        )
        assert res.status_code == 200
        shown_hosts_ids = {obj['id'] for obj in res.json['rows']}
        expected_host_ids = {host.id for host in hosts}
        assert shown_hosts_ids == expected_host_ids

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_verify_severity_counts(self, test_client, session, workspace, host_factory, vulnerability_factory):
        host = host_factory.create(workspace=workspace)
        vulnerability_factory.create(service=None, host=host, workspace=workspace, severity='critical')
        vulnerability_factory.create(service=None, host=host, workspace=workspace, severity='critical')
        vulnerability_factory.create(service=None, host=host, workspace=workspace, severity='high')
        vulnerability_factory.create(service=None, host=host, workspace=workspace, severity='low')
        vulnerability_factory.create(service=None, host=host, workspace=workspace, severity='informational')

        host2 = host_factory.create(workspace=workspace)
        vulnerability_factory.create(service=None, host=host2, workspace=workspace, severity='critical')
        vulnerability_factory.create(service=None, host=host2, workspace=workspace, severity='critical')

        session.commit()

        calc_vulnerability_stats(host.id)
        calc_vulnerability_stats(host2.id)

        res = test_client.get(
            join(
                self.url(),
                f'filter?q={{"filters":[{{"name": "ip", "op":"eq", "val":"{host.ip}"}}]}}'
            )
        )

        assert res.status_code == 200

        severities = res.json['rows'][0]['value']['severity_counts']
        assert severities['info'] == 1
        assert severities['critical'] == 2
        assert severities['high'] == 1
        assert severities['med'] == 0
        assert severities['low'] == 1
        assert severities['unclassified'] == 0
        assert severities['total'] == 5

    def test_filter_by_invalid_service_port(self, test_client, session, workspace,
                                            service_factory, host_factory):
        services = service_factory.create_batch(10, workspace=workspace, port=25)
        hosts = [service.host for service in services]

        # Hosts that shouldn't be shown
        host_factory.create_batch(5, workspace=workspace)

        session.commit()
        res = test_client.get(urljoin(self.url(), '?port=invalid_port'))
        assert res.status_code == 200
        assert res.json['count'] == 0

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_by_invalid_service_port(self, test_client, session, workspace,
                                                     service_factory, host_factory):
        services = service_factory.create_batch(10, workspace=workspace, port=25)
        hosts = [service.host for service in services]

        # Hosts that shouldn't be shown
        host_factory.create_batch(5, workspace=workspace)

        session.commit()
        res = test_client.get(
            join(
                self.url(),
                'filter?q={"filters":[{"name": "services__port", "op":"any", "val":"sarasa"}]}'
            )
        )
        assert res.status_code == 400

    def test_filter_restless_by_invalid_field(self, test_client):
        res = test_client.get(
            join(
                self.url(),
                'filter?q={"filters":[{"name": "severity", "op":"any", "val":"sarasa"}]}'
            )
        )
        assert res.status_code == 400

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_with_no_q_param(self, test_client, session, workspace, host_factory):
        res = test_client.get(join(self.url(), 'filter'))
        assert res.status_code == 200
        assert len(res.json['rows']) == HOSTS_COUNT

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_with_empty_q_param(self, test_client, session, workspace, host_factory):
        res = test_client.get(join(self.url(), 'filter?q'))
        assert res.status_code == 400

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_ip(self, test_client, session, workspace, host_factory):
        host = host_factory.create(ip="longname",
                                   workspace=workspace)
        session.commit()
        res = test_client.get(urljoin(self.url(), '?search=ONGNAM'))
        assert res.status_code == 200
        assert len(res.json['rows']) == 1
        assert res.json['rows'][0]['id'] == host.id

    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.usefixtures('host_services')
    def test_search_service_name(self, test_client, session, workspace,
                                 service_factory):
        expected_hosts = [self.hosts[2], self.hosts[4]]
        for host in expected_hosts:
            service_factory.create(host=host, name="GOPHER 5",
                                   workspace=workspace)
        session.commit()
        res = test_client.get(urljoin(self.url(), '?search=gopher'))
        assert res.status_code == 200
        shown_hosts_ids = {obj['id'] for obj in res.json['rows']}
        expected_host_ids = {host.id for host in expected_hosts}
        assert shown_hosts_ids == expected_host_ids

    @pytest.mark.usefixtures('host_with_hostnames')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_by_hostname(self, test_client, session, workspace):
        expected_hosts = [self.hosts[2], self.hosts[4]]
        for host in expected_hosts:
            host.set_hostnames(['staging.twitter.com'])
        session.commit()
        res = test_client.get(urljoin(self.url(), '?search=twitter'))
        assert res.status_code == 200
        shown_hosts_ids = {obj['id'] for obj in res.json['rows']}
        expected_host_ids = {host.id for host in expected_hosts}
        assert shown_hosts_ids == expected_host_ids

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_host_with_open_vuln_count_verification(self, test_client, session,
                                                    workspace, host_factory,
                                                    vulnerability_factory,
                                                    service_factory):

        host = host_factory.create(workspace=workspace)
        service = service_factory.create(host=host, workspace=workspace)
        vulnerability_factory.create(service=service, host=None, workspace=workspace, severity="low")
        vulnerability_factory.create(service=None, host=host, workspace=workspace, severity="critical")

        session.commit()

        calc_vulnerability_stats(host.id)
        calc_vulnerability_stats(service.host.id)

        res = test_client.get(self.url())
        assert res.status_code == 200
        json_host = list(filter(lambda json_host: json_host['value']['id'] == host.id, res.json['rows']))[0]
        # the host has one vuln associated. another one via service.
        assert json_host['value']['vulns'] == 2
        assert json_host['value']['severity_counts']['critical'] == 1
        assert json_host['value']['severity_counts']['low'] == 1
        assert json_host['value']['severity_counts']['info'] == 0
        assert json_host['value']['severity_counts']['unclassified'] == 0
        assert json_host['value']['severity_counts']['med'] == 0
        assert json_host['value']['severity_counts']['high'] == 0

    def test_host_services_vuln_count_verification(self, test_client, session,
                                                   workspace, host_factory, vulnerability_factory,
                                                   service_factory):
        host = host_factory.create(workspace=workspace)
        service = service_factory.create(host=host, workspace=workspace)
        vulnerability_factory.create(service=service, host=None, workspace=workspace)
        session.commit()

        res = test_client.get(join(self.url(host), 'services'))
        assert res.status_code == 200
        assert res.json[0]['vulns'] == 1

    def test_get_vuln_count(self, test_client, session):
        host = HostFactory.create(workspace=self.workspace)
        session.add(host)
        session.commit()

        severities = ["critical", "high", "medium", "low", "informational", "unclassified"]
        for severity in severities:
            vuln = VulnerabilityFactory.create(
                    workspace=self.workspace,
                    host=host,
                    service=None,
                    severity=severity)
            session.add(vuln)

        session.commit()

        calc_vulnerability_stats(host.id)

        res = test_client.get(join(self.url(), 'countVulns'))
        vuln_count = res.json['hosts'][str(host.id)]

        assert vuln_count['critical'] == 1
        assert vuln_count['high'] == 1
        assert vuln_count['med'] == 1
        assert vuln_count['low'] == 1
        assert vuln_count['info'] == 1
        assert vuln_count['unclassified'] == 1

    def test_add_hosts_from_csv(self, session, test_client, csrf_token):
        ws = WorkspaceFactory.create(name='abc')
        session.add(ws)
        session.commit()
        expected_created_hosts = 2
        file_contents = b"""ip,description,os,hostnames\n
10.10.10.10,test_host,linux,\"['localhost','test_host']\"\n
10.10.10.11,test_host,linux,\"['localhost','test_host_1']"
"""
        data = {
            'file': (BytesIO(file_contents), 'hosts.csv'),
            'csrf_token': csrf_token
        }
        headers = {'Content-type': 'multipart/form-data'}
        res = test_client.post(f'/v3/ws/{ws.name}/hosts/bulk_create',
                               data=data, headers=headers, use_json_data=False)
        assert res.status_code == 200
        assert res.json['hosts_created'] == expected_created_hosts
        assert res.json['hosts_with_errors'] == 0
        assert session.query(Host).filter_by(description="test_host").count() == expected_created_hosts

    def test_bulk_delete_hosts(self, test_client, session):
        host_1 = HostFactory.create(workspace=self.workspace)
        host_2 = HostFactory.create(workspace=self.workspace)
        session.commit()
        hosts_ids = [host_1.id, host_2.id]
        request_data = {'ids': hosts_ids}

        delete_response = test_client.delete(self.url(), data=request_data)

        deleted_hosts = delete_response.json['deleted']
        host_count_after_delete = db.session.query(Host).filter(
            Host.id.in_(hosts_ids),
            Host.workspace_id == self.workspace.id).count()

        assert delete_response.status_code == 200
        assert deleted_hosts == len(hosts_ids)
        assert host_count_after_delete == 0

    def test_bulk_delete_hosts_without_hosts_ids(self, test_client):
        request_data = {'hosts_ids': []}

        delete_response = test_client.delete(self.url(), data=request_data)

        assert delete_response.status_code == 400

    def test_bulk_delete_hosts_from_another_workspace(self, test_client, session):
        workspace_1 = WorkspaceFactory.create(name='workspace_1')
        host_of_ws_1 = HostFactory.create(workspace=workspace_1)
        workspace_2 = WorkspaceFactory.create(name='workspace_2')
        host_of_ws_2 = HostFactory.create(workspace=workspace_2)
        session.commit()

        # Try to delete workspace_2's host from workspace_1
        request_data = {'ids': [host_of_ws_2.id]}
        delete_response = test_client.delete(self.url(), data=request_data)

        assert delete_response.status_code == 200
        assert delete_response.json['deleted'] == 1

    def test_bulk_delete_hosts_invalid_characters_in_request(self, test_client):
        ws = WorkspaceFactory.create(name="abc")
        request_data = {'ids': [-1, 'test']}
        delete_response = test_client.delete(self.url(), data=request_data)

        assert delete_response.json['deleted'] == 0

    def test_bulk_delete_hosts_wrong_content_type(self, test_client, session):
        ws = WorkspaceFactory.create(name="abc")
        host_1 = HostFactory.create(workspace=ws)
        host_2 = HostFactory.create(workspace=ws)
        session.commit()
        hosts_ids = [host_1.id, host_2.id]

        request_data = {'ids': hosts_ids}
        headers = [('content-type', 'text/xml')]

        delete_response = test_client.delete(
            self.url(),
            data=request_data,
            headers=headers)

        assert delete_response.status_code == 400

    def test_bulk_delete_with_references(self, test_client, session, workspace, host_factory, vulnerability_factory,
                                         service_factory):
        host_1 = host_factory.create(workspace=workspace)
        service_factory.create(host=host_1, workspace=workspace)
        vulnerability_factory.create(service=None, host=host_1, workspace=workspace)
        host_1.hostnames.append(HostnameFactory.create(name='pepe1', workspace=workspace, host=host_1))

        host_2 = host_factory.create(workspace=workspace)
        service_factory.create(host=host_2, workspace=workspace)
        vulnerability_factory.create(service=None, host=host_2, workspace=workspace)
        host_1.hostnames.append(HostnameFactory.create(name='pepe2', workspace=workspace, host=host_2))

        session.commit()

        hosts_ids = [host_1.id, host_2.id]
        request_data = {'ids': hosts_ids}
        delete_response = test_client.delete(self.url(), data=request_data)

        assert delete_response.status_code == 200
        assert delete_response.json['deleted'] == 2


@pytest.mark.skip_sql_dialect('sqlite')
class TestHostAPIGeneric(ReadOnlyAPITests, PaginationTestsMixin, BulkUpdateTestsMixin, BulkDeleteTestsMixin):
    model = Host
    factory = factories.HostFactory
    api_endpoint = 'hosts'
    unique_fields = ['ip']
    update_fields = ['ip', 'description', 'os']
    patchable_fields = update_fields
    view_class = HostView
    pk_field = 'id'
    objects = []

    @pytest.fixture(autouse=True)
    def load_many_objects(self, database, session, workspace):
        self.objects = self.factory.create_batch(
            HOSTS_COUNT, workspace=workspace)
        self.first_object = self.objects[0]
        session.add_all(self.objects)
        session.commit()
        assert workspace.id is not None
        self.workspace = workspace
        return workspace

    @pytest.fixture
    def mock_envelope_list(self, monkeypatch):
        assert self.view_class is not None, 'You must define view_class ' \
                                            'in order to use ListTestsMixin or PaginationTestsMixin'

        def _envelope_list(_, objects, pagination_metadata=None):
            return {"data": objects}

        monkeypatch.setattr(self.view_class, '_envelope_list', _envelope_list)

    def test_tool_impacted_by_host(self, test_client, session):
        from tests.factories import EmptyCommandFactory, CommandObjectFactory
        command = EmptyCommandFactory.create(workspace=self.workspace)
        CommandObjectFactory.create(
            command=command,
            object_type='host',
            object_id=self.objects[0].id,
            workspace=command.workspace
        )
        session.commit()
        res = test_client.get(join(self.url(self.objects[0].id), 'tools_history'))
        assert len(res.json['tools']) == 1
        assert res.json['tools'][0]['command'] == command.tool
        assert res.json['tools'][0]['user'] == command.user

    @pytest.mark.usefixtures("mock_envelope_list")
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_sort_by_description(self, test_client, session):
        for host in Host.query.all():
            # I don't want to test case-sensitive sorting
            host.description = host.description.lower()
        session.commit()
        expected_ids = [host.id for host in
                        sorted(Host.query.all(),
                               key=operator.attrgetter('description'))]
        res = test_client.get(urljoin(self.url(), '?sort=description&sort_dir=asc'))
        assert res.status_code == 200
        assert [host['_id'] for host in res.json['data']] == expected_ids

        expected_ids.reverse()  # In place list reverse
        res = test_client.get(urljoin(self.url(), '?sort=description&sort_dir=desc'))
        assert res.status_code == 200
        assert [host['_id'] for host in res.json['data']] == expected_ids

    @pytest.mark.usefixtures("mock_envelope_list")
    @pytest.mark.usefixtures('ignore_nplusone')
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
        res = test_client.get(urljoin(self.url(),
                                      '?sort=services&sort_dir=asc'))
        assert res.status_code == 200
        assert [h['_id'] for h in res.json['data'] if h['_id'] in expected_ids] == expected_ids

    @pytest.mark.usefixtures("mock_envelope_list")
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_sort_by_update_time(self, test_client, session, second_workspace,
                                 host_factory):
        """
        This test doesn't test only the hosts view, but all the ones that
        expose an object with metadata.
        Think twice if you are thinking in removing it
        """
        expected = Host.query.all()
        session.commit()
        for i in range(len(expected)):
            if i % 2 == 0:  # Only update some hosts
                host = expected.pop(0)
                host.description = 'i was updated'
                session.add(host)
                session.commit()
                expected.append(host)  # Put it on the end
        res = test_client.get(urljoin(self.url(),
                               '?sort=metadata.update_time&sort_dir=asc'))
        assert res.status_code == 200, res.data
        assert [h['_id'] for h in res.json['data']] == [h.id for h in expected]

    def test_service_summaries(self, test_client, session, service_factory):
        service_factory.create(name='http', protocol='tcp', port=80,
                               host=self.first_object, status='open',
                               version='nginx',
                               workspace=self.workspace)
        service_factory.create(name='https', protocol='tcp', port=443,
                               host=self.first_object, status='open',
                               version=None,
                               workspace=self.workspace)
        service_factory.create(name='dns', protocol='udp', port=5353,
                               host=self.first_object, status='open',
                               version=None,
                               workspace=self.workspace)
        service_factory.create(name='smtp', protocol='tcp', port=25,
                               host=self.first_object, status='filtered',
                               version=None,
                               workspace=self.workspace)
        service_factory.create(name='dns', protocol='udp', port=53,
                               host=self.first_object, status='open',
                               version=None,
                               workspace=self.workspace)
        service_factory.create(name='other', protocol='udp', port=1234,
                               host=self.first_object, status='closed',
                               version=None,
                               workspace=self.workspace)
        session.commit()
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        service_summaries = res.json['service_summaries']
        assert service_summaries == [
            '(80/tcp) http (nginx)',
            '(443/tcp) https',
            '(53/udp) dns',
            '(5353/udp) dns',
        ]

    @pytest.mark.skip  # TODO un-skip
    def test_hosts_ordered_by_vulns_severity(self, session, test_client, service_factory,
                                             vulnerability_factory, vulnerability_web_factory):
        ws = WorkspaceFactory.create()
        session.add(ws)
        hosts_list = []
        for i in range(0, 10):
            host = HostFactory.create(workspace=ws)
            session.add(host)
            service = service_factory.create(workspace=ws, host=host)
            session.add(service)
            hosts_list.append(host)
        session.commit()

        severities = ['critical', 'high', 'medium', 'low', 'informational', 'unclassified']
        # Vulns counter by severity in host
        vulns_by_severity = {host.id: [0, 0, 0, 0, 0, 0] for host in hosts_list}

        for host in hosts_list:
            # Each host has 10 vulns
            for i in range(0, 10):
                vuln_web = choice([True, False])
                severity = choice(severities)

                if vuln_web:
                    vuln = vulnerability_web_factory.create(
                        workspace=ws, service=host.services[0], severity=severity
                    )
                else:
                    vuln = vulnerability_factory.create(
                        host=None, service=host.services[0],
                        workspace=host.workspace, severity=severity
                    )
                session.add(vuln)

                # Increase 1 to number of vulns by severity in the host
                vulns_by_severity[host.id][severities.index(severity)] += 1
        session.commit()

        # Sort vulns_by_severity by number of vulns by severity in every host
        sorted_hosts = sorted(
            vulns_by_severity.items(),
            key=lambda host: [vuln_count for vuln_count in host[1]],
            reverse=True
        )

        res = test_client.get(self.url())
        assert res.status_code == 200

        response_hosts = res.json['rows']
        for host in response_hosts:
            # sorted_hosts and response_hosts have the same order so the index
            # of host in sorted_host is the same as the
            # index of host in response_hosts
            index_in_sorted_host = [host_tuple[0] for host_tuple in sorted_hosts].index(host['id'])
            index_in_response_hosts = response_hosts.index(host)

            assert index_in_sorted_host == index_in_response_hosts

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_hosts_order_without_vulns(self, session, test_client):
        # If a host has no vulns, it should be ordered by IP in ascending order
        ws = WorkspaceFactory.create()
        session.add(ws)
        hosts_ids = []
        for i in range(0, 10):
            host = HostFactory.create(workspace=ws, ip=f'127.0.0.{i}')
            session.add(host)
            hosts_ids.append(host.id)
        session.commit()
        res = test_client.get(self.url())
        assert res.status_code == 200

        response_hosts = res.json['rows']
        for host in response_hosts:
            if host['id'] in hosts_ids:
                # hosts_ids and response_hosts have the same order so the index
                # of host in hosts_ids is the same as the
                # index of host in response_hosts
                index_in_hosts_ids = hosts_ids.index(host['id'])
                index_in_response_hosts = response_hosts.index(host)

                assert index_in_hosts_ids == index_in_response_hosts

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_bulk_update_host_with_hostnames(self, test_client, session,
                                        host_with_hostnames):
        session.commit()
        data = {
            "ids": [host_with_hostnames.id, self.first_object.id],
            "hostnames": ["other.com", "test.com"],
        }
        res = test_client.patch(self.url(), data=data)
        assert res.status_code == 200
        assert res.json["updated"] == 2
        expected = {"other.com", "test.com"}
        assert {hn.name for hn in host_with_hostnames.hostnames} == expected
        assert {hn.name for hn in self.first_object.hostnames} == expected

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_bulk_update_host_without_hostnames(self, test_client, session,
                                                host_with_hostnames):
        session.commit()
        expected = {hn.name for hn in host_with_hostnames.hostnames}
        data = {
            "ids": [host_with_hostnames.id],
            "os": "NotAnOS"
        }
        res = test_client.patch(self.url(), data=data)
        assert res.status_code == 200
        assert res.json["updated"] == 1
        assert {hn.name for hn in host_with_hostnames.hostnames} == expected

    def test_bulk_update_fails_with_existing(self, test_client, session):
        for unique_field in self.unique_fields:
            data = self.factory.build_dict()
            data[unique_field] = getattr(self.objects[3], unique_field)
            data["ids"] = [getattr(self.objects[i], self.view_class.lookup_field) for i in range(0, 2)]
            res = test_client.patch(self.url(), data=data)
            assert res.status_code == 409
            assert self.model.query.count() == HOSTS_COUNT
            assert res.json['message'] == 'Existing value'


def host_json():
    return st.fixed_dictionaries(
        {
            "metadata":
                st.fixed_dictionaries({
                    "update_time": st.floats(),
                    "update_user": st.one_of(st.none(), st.text()),
                    "update_action": st.integers(),
                    "creator": st.text(),
                    "create_time": st.integers(),
                    "update_controller_action": st.text(),
                    "owner": st.one_of(st.none(), st.text()),
                    "command_id": st.one_of(st.none(), st.text(), st.integers()), }),
            "name": st.one_of(st.none(), st.text()),
            "ip": st.one_of(st.none(), st.text()),
            "_rev": st.one_of(st.none(), st.text()),
            "description": st.one_of(st.none(), st.text()),
            "default_gateway": st.one_of(st.none(), st.text()),
            "owned": st.booleans(),
            "services": st.one_of(st.none(), st.integers()),
            "hostnames": st.lists(st.text()),
            "vulns": st.one_of(st.none(), st.integers()),
            "owner": st.one_of(st.none(), st.text()),
            "_id": st.one_of(st.none(), st.integers()),
            "os": st.one_of(st.none(), st.text()),
            "id": st.one_of(st.none(), st.integers()),
            "icon": st.one_of(st.none(), st.text())}
    )


@pytest.mark.usefixtures('logged_user')
@pytest.mark.hypothesis
def test_hypothesis(host_with_hostnames, test_client, session):
    session.commit()
    HostData = host_json()

    @given(HostData)
    def send_api_request(raw_data):
        ws_name = host_with_hostnames.workspace.name
        res = test_client.post(f'/v3/ws/{ws_name}/vulns',
                               data=raw_data)
        assert res.status_code in [201, 400, 409]

    send_api_request()
