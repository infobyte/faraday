"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
from datetime import date, timedelta
from json import dumps
from urllib.parse import quote

# Related third party imports
import pytest
from flask import g
from flask_sqlalchemy.record_queries import get_recorded_queries

# Local application imports
from faraday.server.models import Scope, SeveritiesHistogram, VulnerabilityReference
from tests import factories

#: What the UI asks for: one page of results.
PAGE = quote(dumps({"filters": [], "limit": 50, "offset": 0}))
NO_FILTERS = quote(dumps({"filters": []}))


def _count_queries(test_client, session, url):
    """Issue a GET on a cold session and return how many SQL statements it took.

    Expiring the session is what makes an N+1 visible: without it the objects
    loaded by a previous request stay in the identity map and no lazy load is
    emitted. The extra request re-loads the logged user so its queries are not
    counted, which also makes two measurements comparable.
    """
    session.expire_all()
    test_client.get('/v3/info')
    g._sqlalchemy_queries = []
    res = test_client.get(url)
    assert res.status_code == 200, res.json
    return len(get_recorded_queries()), res


def _make_workspaces(session, prefix, amount, credentials=1):
    for i in range(amount):
        workspace = factories.WorkspaceFactory.create(name=f'{prefix}{i}')
        session.add(workspace)
        session.flush()
        session.add(Scope(name=f'10.0.0.{i}', workspace=workspace))
        for _ in range(credentials):
            session.add(factories.CredentialFactory.create(workspace=workspace))
    session.commit()
    session.expire_all()


def _add_assets(session, workspace, label, hosts):
    """Hosts with hostnames, services and vulns hanging off both parents."""
    for h in range(hosts):
        host = factories.HostFactory.create(workspace=workspace)
        session.add(host)
        session.flush()
        session.add(factories.HostnameFactory.create(
            workspace=workspace, host=host, name=f'{label}-{h}.example.com'))
        service = factories.ServiceFactory.create(workspace=workspace, host=host)
        session.add(service)
        session.flush()
        # One vuln on the host and one on the service: `service` is declared
        # per polymorphic subclass, so both parents need eager loading.
        for parent in ({'host': host, 'service': None}, {'host': None, 'service': service}):
            vuln = factories.VulnerabilityFactory.create(
                workspace=workspace, severity='high', **parent)
            session.add(vuln)
            session.flush()
            vuln.refs = [VulnerabilityReference(name=f'REF-{label}-{h}')]
            vuln.policy_violations = ['pv-1']
            vuln.cve = ['CVE-2024-1111']
        session.add(factories.VulnerabilityWebFactory.create(
            workspace=workspace, service=service, severity='medium'))
    session.commit()
    session.expire_all()


def _make_histograms(session, prefix, amount):
    """Workspaces that each have a severities histogram row."""
    for i in range(amount):
        workspace = factories.WorkspaceFactory.create(name=f'{prefix}{i}')
        session.add(workspace)
        session.flush()
        session.add(SeveritiesHistogram(
            workspace=workspace, date=date.today() - timedelta(days=1),
            medium=1, high=2, critical=3, confirmed=1))
    session.commit()
    session.expire_all()


def _make_assets(session, prefix, workspaces_amount, hosts_per_workspace=3):
    for w in range(workspaces_amount):
        workspace = factories.WorkspaceFactory.create(name=f'{prefix}{w}')
        session.add(workspace)
        session.flush()
        _add_assets(session, workspace, f'{prefix}{w}', hosts_per_workspace)


def _get_workspace(name):
    return factories.WorkspaceFactory._meta.model.query.filter_by(name=name).one()


@pytest.mark.usefixtures('logged_user')
class TestQueryCounts:
    """The listing endpoints must run a constant number of queries: adding
    rows may not add queries (N+1). See faraday.server.app.log_queries_count,
    which warns above 15 queries per request."""

    def test_workspace_filter_query_count_is_constant(self, test_client, session):
        _make_workspaces(session, 'qcws', 3)
        few, _ = _count_queries(test_client, session, f'/v3/ws/filter?q={NO_FILTERS}')

        _make_workspaces(session, 'qcwsmore', 12)
        many, res = _count_queries(test_client, session, f'/v3/ws/filter?q={NO_FILTERS}')

        assert res.json['count'] >= 15
        assert many <= few, f"Workspace filter scales with rows: {few} -> {many}"

    @pytest.mark.parametrize('url', ['/v3/ws/filter?q={no_filters}&histogram=true',
                                     '/v3/ws?histogram=true'])
    def test_workspace_histogram_query_count_is_constant(self, test_client, session, url):
        """generate_histogram groups the rows by workspace name, which lazy-loads
        one workspace per histogram row unless it is eager loaded."""
        url = url.format(no_filters=NO_FILTERS)
        _make_histograms(session, 'qchist', 3)
        few, _ = _count_queries(test_client, session, url)

        _make_histograms(session, 'qchistmore', 12)
        many, res = _count_queries(test_client, session, url)

        rows = res.json['rows']
        assert len(rows) >= 15
        assert all(row['histogram'] for row in rows)
        assert many <= few, f"{url} scales with rows: {few} -> {many}"

    def test_workspace_filter_still_dumps_scope_and_credentials(self, test_client, session):
        _make_workspaces(session, 'qcwsdump', 1, credentials=2)
        _, res = _count_queries(test_client, session, f'/v3/ws/filter?q={NO_FILTERS}')

        row = next(r for r in res.json['rows'] if r['name'] == 'qcwsdump0')
        assert row['scope'] == [{'name': '10.0.0.0'}]
        assert row['stats']['credentials'] == 2

    @pytest.mark.parametrize('url', [
        '/v3/vulns/filter?q={page}',
        '/v3/ws/qcv0/vulns/filter?q={page}',
        '/v3/vulns?page_number=1&page_size=50',
        '/v3/ws/qcv0/vulns?page_number=1&page_size=50',
        '/v3/hosts/filter?q={page}',
        '/v3/ws/qcv0/hosts/filter?q={page}',
        '/v3/services/filter?q={page}',
        '/v3/ws/qcv0/services/filter?q={page}',
    ])
    def test_listing_query_count_is_constant(self, test_client, session, url):
        url = url.format(page=PAGE)
        # qcv0 is the workspace the workspaced urls above point at; it grows
        # from 2 to 8 hosts between the two measurements.
        _make_assets(session, 'qcv', 2, hosts_per_workspace=2)
        few, _ = _count_queries(test_client, session, url)

        _make_assets(session, 'qcvmore', 4, hosts_per_workspace=2)
        _add_assets(session, _get_workspace('qcv0'), 'qcvgrown', 6)
        many, res = _count_queries(test_client, session, url)

        assert res.json['count'] >= 1
        assert many <= few, f"{url} scales with rows: {few} -> {many}"

    def test_workspaced_listings_stay_flat_as_the_workspace_grows(self, test_client, session):
        """The workspaced /filter routes use FilterWorkspacedMixin, a different
        query builder than the non-workspaced ones, so they need their own check."""
        _make_assets(session, 'qcgrow', 1, hosts_per_workspace=2)
        urls = [
            f'/v3/ws/qcgrow0/vulns/filter?q={PAGE}',
            f'/v3/ws/qcgrow0/hosts/filter?q={PAGE}',
            f'/v3/ws/qcgrow0/services/filter?q={PAGE}',
        ]
        few = {url: _count_queries(test_client, session, url)[0] for url in urls}

        _add_assets(session, _get_workspace('qcgrow0'), 'qcgrown', 10)

        for url in urls:
            many, _ = _count_queries(test_client, session, url)
            assert many <= few[url], f"{url} scales with rows: {few[url]} -> {many}"

    def test_vulns_listings_still_dump_related_data(self, test_client, session):
        _make_assets(session, 'qcvdump', 1, hosts_per_workspace=1)

        for url in (f'/v3/vulns/filter?q={PAGE}', '/v3/vulns'):
            _, res = _count_queries(test_client, session, url)
            rows = [row['value'] for row in res.json['vulnerabilities']]
            on_service = next(r for r in rows if r['parent_type'] == 'Service'
                              and r['type'] == 'Vulnerability')
            assert on_service['workspace_name'] == 'qcvdump0'
            assert on_service['service']['name']
            assert on_service['hostnames'] == ['qcvdump0-0.example.com']

        # refs / policyviolations are excluded from the filter dump by default,
        # so they are only checked on the index route.
        _, res = _count_queries(test_client, session, '/v3/vulns')
        rows = [row['value'] for row in res.json['vulnerabilities']]
        on_service = next(r for r in rows if r['parent_type'] == 'Service'
                          and r['type'] == 'Vulnerability')
        assert [ref['name'] for ref in on_service['refs']] == ['REF-qcvdump0-0']
        assert on_service['policyviolations'] == ['pv-1']
        assert on_service['cve'] == ['CVE-2024-1111']

    def test_services_filter_still_dumps_host_owner_and_workspace(self, test_client, session, workspace):
        host = factories.HostFactory.create(workspace=workspace, ip='9.9.9.9')
        session.add(host)
        session.flush()
        service = factories.ServiceFactory.create(workspace=workspace, host=host, name='qcsvc')
        session.add(service)
        session.commit()

        for url in (f'/v3/services/filter?q={PAGE}',
                    f'/v3/ws/{workspace.name}/services/filter?q={PAGE}'):
            _, res = _count_queries(test_client, session, url)
            row = next(r for r in res.json['services'] if r['value']['name'] == 'qcsvc')['value']
            assert row['parent_name'] == '9.9.9.9'
            assert row['workspace_name'] == workspace.name
            assert row['owner'] == service.creator.username

    def test_hosts_filter_still_dumps_hostnames_services_and_workspace(self, test_client, session, workspace):
        host = factories.HostFactory.create(workspace=workspace, ip='8.8.8.8')
        session.add(host)
        session.flush()
        session.add(factories.HostnameFactory.create(
            workspace=workspace, host=host, name='qchost.example.com'))
        session.add(factories.ServiceFactory.create(
            workspace=workspace, host=host, name='qcsvc', status='open'))
        session.commit()

        for url in (f'/v3/hosts/filter?q={PAGE}',
                    f'/v3/ws/{workspace.name}/hosts/filter?q={PAGE}'):
            _, res = _count_queries(test_client, session, url)
            row = next(r for r in res.json['rows'] if r['value']['ip'] == '8.8.8.8')['value']
            assert row['workspace_name'] == workspace.name
            assert row['hostnames'] == ['qchost.example.com']
            assert row['owner'] == host.creator.username
            assert any('qcsvc' in summary for summary in row['service_summaries'])
