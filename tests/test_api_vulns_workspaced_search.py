import csv
import json
import datetime
from io import BytesIO, StringIO

import pytest

from faraday.server.utils.vulns import VALID_FILTER_VULN_COLUMNS
from tests.factories import (
    HostFactory,
    HostnameFactory,
    ServiceFactory,
    VulnerabilityFactory,
    VulnerabilityWebFactory,
    WorkspaceFactory,
)
from faraday.server.models import File


@pytest.mark.usefixtures('logged_user')
class TestVulnerabilitySearch:

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.skip(reason="We need a better solution for searching by hostnames.")
    def test_search_by_hostname_vulns(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create_batch(10, workspace=workspace)
        # host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        vuln = VulnerabilityFactory.create(host=host[0], service=None, workspace=workspace)
        vuln2 = VulnerabilityFactory.create(host=host[1], service=None, workspace=workspace)
        session.add_all([vuln, vuln2])
        session.add_all(host)
        session.commit()
        session.refresh(vuln)
        session.refresh(vuln2)

        query_filter = {"filters":
                            [{"name": "hostnames", "op": "eq", "val": "pepe"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.skip(reason="We need a better solution for searching by hostnames.")
    def test_search_by_hostname_vulns_with_service(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        service = ServiceFactory.create(host=host, workspace=workspace)
        vuln = VulnerabilityFactory.create(host=None, service=service, workspace=workspace)
        session.add(vuln)
        session.add(host)
        session.commit()
        session.refresh(vuln)

        query_filter = {"filters":
                            [{"name": "hostnames", "op": "eq", "val": "pepe"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.skip(reason="We need a better solution for searching by hostnames.")
    def test_search_hostname_web_vulns(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        service = ServiceFactory.create(host=host, workspace=workspace)
        vuln = VulnerabilityWebFactory.create(service=service, workspace=workspace)
        session.add(vuln)
        session.add(host)
        session.commit()
        session.refresh(vuln)

        query_filter = {"filters":
                            [{"name": "hostnames", "op": "eq", "val": "pepe"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    def test_search_empty_filters(self, workspace, test_client, session):
        query_filter = {"filters":
                            []
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 0

    def test_search_code_attribute_bug(self, workspace, test_client, session):
        query_filter = {"filters":
                            [{"name": "code", "op": "eq", "val": "test"}]
                        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )

        assert res.status_code == 400, res.json

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_by_hostname_multiple_logic(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        host.hostnames.append(HostnameFactory.create(name='pepe', workspace=workspace))
        vuln = VulnerabilityFactory.create(host=host, service=None, workspace=workspace)
        session.add(vuln)
        session.add(host)
        session.commit()

        query_filter = {"filters": [
            {"and": [{"name": "hostnames", "op": "eq", "val": "pepe"}]}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_filter_offset_and_limit_mixed_vulns_type_bug(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityFactory.create_batch(10,
                                                  workspace=workspace,
                                                  severity='high'
                                                  )
        session.add_all(vulns)
        web_vulns = VulnerabilityWebFactory.create_batch(10,
                                                         workspace=workspace,
                                                         severity='high'
                                                         )
        session.add_all(web_vulns)
        session.add(host)
        session.commit()
        paginated_vulns = set()
        expected_vulns = set([vuln.id for vuln in vulns] + [vuln.id for vuln in web_vulns])
        for offset in range(0, 2):
            query_filter = {
                "filters": [{"name": "severity", "op": "eq", "val": "high"}],
                "limit": 10,
                "offset": offset * 10,
            }
            res = test_client.get(
                f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
            )
            assert res.status_code == 200
            assert res.json['count'] == 20, query_filter
            assert len(res.json['vulnerabilities']) == 10
            for vuln in res.json['vulnerabilities']:
                paginated_vulns.add(vuln['id'])
        assert expected_vulns == paginated_vulns

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_filter_offset_and_limit_page_size_10(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(100,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        session.add(host)
        session.commit()
        paginated_vulns = set()
        expected_vulns = {vuln.id for vuln in vulns}
        for offset in range(0, 10):
            query_filter = {
                "filters": [{"name": "severity", "op": "eq", "val": "high"}],
                "limit": 10,
                "offset": 10 * offset,
            }
            res = test_client.get(
                f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
            )
            assert res.status_code == 200
            assert res.json['count'] == 100
            for vuln in res.json['vulnerabilities']:
                paginated_vulns.add(vuln['id'])
        assert expected_vulns == paginated_vulns

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_filter_offset_and_limit(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(10,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        vulns = VulnerabilityFactory.create_batch(10,
                                                  workspace=workspace,
                                                  severity='low'
                                                  )
        session.add_all(vulns)
        med_vulns = VulnerabilityFactory.create_batch(10,
                                                      workspace=workspace,
                                                      severity='medium'
                                                      )
        session.add_all(med_vulns)
        session.add(host)
        session.commit()
        paginated_vulns = set()
        expected_vulns = {vuln.id for vuln in med_vulns}
        for offset in range(0, 10):
            query_filter = {
                "filters": [{"name": "severity", "op": "eq", "val": "medium"}],
                "limit": "1",
                "offset": offset,
            }
            res = test_client.get(
                f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
            )
            assert res.status_code == 200
            assert res.json['count'] == 10
            paginated_vulns.add(res.json['vulnerabilities'][0]['id'])

        assert expected_vulns == paginated_vulns

    def test_vuln_get_limit(self, test_client, session):

        # Change setting
        test_client.patch('/v3/settings/query_limits', data={"vuln_query_limit": 25})

        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(50,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        session.add(host)
        session.commit()

        res = test_client.get(f'/v3/ws/{workspace.name}/vulns')

        assert res.status_code == 200
        assert res.json['count'] == 50
        assert len(res.json['vulnerabilities']) == 25

    @pytest.mark.parametrize("limit", [
        ["5", 5],
        [None, 25],
        ["100", 25]
    ])
    def test_vuln_filter_limit(self, test_client, session, limit):

        # Change setting
        test_client.patch('/v3/settings/query_limits', data={"vuln_query_limit": 25})

        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        vulns = VulnerabilityWebFactory.create_batch(50,
                                                     workspace=workspace,
                                                     severity='high'
                                                     )
        session.add_all(vulns)
        session.add(host)
        session.commit()

        if limit[0] is None:
            query_filter = {}
        else:
            query_filter = {
                "filters": [],
                "limit": limit[0],
                "offset": "1",
            }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 50
        assert len(res.json['vulnerabilities']) == limit[1]

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.skip(reason="We need a better solution for searching in the model.")
    def test_search_by_host_os_with_vulnerability_web_bug(self, test_client, session):
        """
            When searching by the host os an error was raised when a vuln web exists in the ws
        """
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace, os='Linux')
        service = ServiceFactory.create(host=host, workspace=workspace)
        vuln = VulnerabilityFactory.create(
            service=service,
            confirmed=True,
            workspace=workspace,
        )
        host2 = HostFactory.create(workspace=workspace, os='OS/2')
        vuln2 = VulnerabilityFactory.create(
            confirmed=True,
            host=host2,
            service=None,
            workspace=workspace,
        )
        session.add(vuln)
        session.add(vuln2)
        session.add(host)
        session.commit()

        query_filter = {"filters": [
            {"name": "host__os", "op": "has", "val": "Linux"}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['vulnerabilities'][0]['id'] == vuln.id

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_search_by_date_equals(self, test_client, session):
        """
            When searching by the host os an error was raised when a vuln web exists in the ws
        """
        workspace = WorkspaceFactory.create()
        service = ServiceFactory.create(workspace=workspace)
        vuln = VulnerabilityWebFactory.create(
            service=service,
            confirmed=True,
            workspace=workspace,
            create_date=datetime.datetime(2020, 7, 8)
        )
        vuln2 = VulnerabilityFactory.create(
            confirmed=True,
            service=None,
            workspace=workspace,
            create_date=datetime.datetime(2020, 7, 8, 13, 59, 59)
        )
        vuln3 = VulnerabilityFactory.create(
            confirmed=True,
            service=None,
            workspace=workspace,
            create_date=datetime.datetime(2020, 7, 8, 23, 59, 59)
        )
        vuln4 = VulnerabilityFactory.create(
            confirmed=True,
            service=None,
            workspace=workspace,
            create_date=datetime.datetime(2019, 7, 8, 23, 59, 59)
        )
        session.add(vuln)
        session.add(vuln2)
        session.add(vuln3)
        session.add(vuln4)
        session.commit()

        query_filter = {"filters": [
            {"name": "create_date", "op": "eq", "val": vuln.create_date.strftime("%Y-%m-%d")}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 3

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_by_date_equals_invalid_date(self, test_client, session):
        """
            When searching by the host os an error was raised when a vuln web exists in the ws
        """
        workspace = WorkspaceFactory.create()
        query_filter = {"filters": [
            {"name": "create_date", "op": "eq", "val": "30/01/2020"}
        ]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'host_id', 'op': 'not_in',
                                     'val': '\U0010a1a7\U00093553\U000eb46a\x1e\x10\r\x18%\U0005ddfa0\x05\U000fdeba\x08\x04絮'}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_2(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'host__os', 'op': 'ilike', 'val': -1915870387}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'workspace_id', 'op': '==', 'val': ''}]},
        {'filters': [{'name': 'type', 'op': '==', 'val': -24286}]},
        {'filters': [{'name': 'risk', 'op': 'ilike', 'val': -881419975}]},
    ])
    def test_search_hypothesis_test_found_case_3(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'workspace_id', 'op': 'in', 'val': 56}]},
        {'filters': [{'name': 'creator', 'op': 'in', 'val': 56}]},
        {'filters': [{'name': 'creator_id', 'op': 'not_in', 'val': 0}]}
    ])
    def test_search_hypothesis_test_found_case_4(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'creator', 'op': 'geq', 'val': 27576}, {'name': 'name', 'op': 'eq', 'val': None}]},
        {'filters': [{'name': 'impact_confidentiality', 'op': 'ge', 'val': 0}]},
        {'filters': [{'name': 'creator', 'op': 'eq', 'val': -22}]}
    ])
    def test_search_hypothesis_test_found_case_5(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_6(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'resolution', 'op': '==', 'val': ''}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_7(self, test_client, session, workspace):
        query_filter = {'filters': [
            {'name': 'name', 'op': '>', 'val': '\U0004e755\U0007a789\U000e02d1\U000b3d32\x10\U000ad0e2,\x05\x1a'},
            {'name': 'creator', 'op': 'eq', 'val': 21883}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize('query_filter', [
        {'filters': [{'name': 'id', 'op': '>', 'val': 3}]},
        {'filters': [{'name': 'create_date', 'op': '>', 'val': '2020-10-10'}]}
    ])
    def test_search_hypothesis_test_found_case_7_valid(self, query_filter, test_client, session, workspace):
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_8(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'hostnames', 'op': '==', 'val': ''}]}
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_9(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'issuetracker', 'op': 'not_equal_to',
                                     'val': '0\x00\U00034383$\x13-\U000375fb\U0007add2\x01\x01\U0010c23a'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_10(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'impact_integrity', 'op': 'neq', 'val': 0}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_11(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'host_id', 'op': 'like', 'val': '0'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    # TODO: Add new tests for custom_fields filters
    @pytest.mark.skip
    def test_search_hypothesis_test_found_case_12(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'custom_fields', 'op': 'like', 'val': ''}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_search_hypothesis_test_found_case_13(self, test_client, session, workspace):
        query_filter = {'filters': [{'name': 'impact_accountability', 'op': 'ilike', 'val': '0'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_count(self, test_client, session, workspace):
        vulns_web = VulnerabilityWebFactory.create_batch(10, workspace=workspace, severity='high')
        vulns = VulnerabilityFactory.create_batch(10, workspace=workspace, severity='high')
        another_workspace = WorkspaceFactory.create()
        more_vulns = VulnerabilityFactory.create_batch(10, workspace=another_workspace, severity='high')
        session.add_all(more_vulns)
        session.add_all(vulns_web)
        session.add_all(vulns)
        session.commit()
        query_filter = {'filters': [{'name': 'severity', 'op': 'eq', 'val': 'high'}]}

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 20

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_group_and_sort(self, test_client, session, workspace):
        vulns_web = VulnerabilityWebFactory.create_batch(10, workspace=workspace, severity='high')
        vulns = VulnerabilityFactory.create_batch(10, workspace=workspace, severity='high')
        another_workspace = WorkspaceFactory.create()
        more_vulns = VulnerabilityFactory.create_batch(10, workspace=another_workspace, severity='high')
        session.add_all(more_vulns)
        session.add_all(vulns_web)
        session.add_all(vulns)
        session.commit()
        query_filter = {
            "group_by":
                [{"field": "severity"}],
            "order_by":
                [{"field": "name", "direction": "asc"}]
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 400

    def test_filter_order_by_without_filters_fix_500_error(self, test_client, session, workspace):
        query_filter = {
            "order_by":
                [{"field": "cve_instances__name", "direction": "desc"}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.parametrize("sort_order", [
        {"direction": "asc", "expected": ['a', 'A', 'b', 'B']},
        {"direction": "desc", "expected": ['B', 'b', 'A', 'a']}
    ])
    def test_filter_order_by_name_directions(self, sort_order, test_client, session, workspace):
        vuln_1 = VulnerabilityWebFactory.create(name='a', workspace=workspace, severity='high')
        vuln_2 = VulnerabilityWebFactory.create(name='b', workspace=workspace, severity='high')
        vuln_3 = VulnerabilityWebFactory.create(name='A', workspace=workspace, severity='high')
        vuln_4 = VulnerabilityWebFactory.create(name='B', workspace=workspace, severity='high')

        session.add_all([vuln_1, vuln_2, vuln_3, vuln_4])
        session.commit()
        query_filter = {
            "order_by":
                [{"field": "name", "direction": sort_order["direction"]}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        expected_order = sort_order["expected"]

        assert expected_order == [vuln['value']['name'] for vuln in res.json['vulnerabilities']]

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_filter_order_by_severity(self, test_client, session, workspace):
        vuln_4 = VulnerabilityWebFactory.create(name='B', workspace=workspace, severity='low')
        vuln_1 = VulnerabilityWebFactory.create(name='a', workspace=workspace, severity='critical')
        vuln_3 = VulnerabilityWebFactory.create(name='A', workspace=workspace, severity='medium')
        vuln_2 = VulnerabilityWebFactory.create(name='b', workspace=workspace, severity='high')

        session.add_all([vuln_1, vuln_2, vuln_3, vuln_4])
        session.commit()
        query_filter = {
            "order_by":
                [{"field": "severity", "direction": "desc"}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        expected_order = ['critical', 'high', 'med', 'low']

        assert expected_order == [vuln['value']['severity'] for vuln in res.json['vulnerabilities']]

        query_filter = {
            "order_by":
                [{"field": "severity", "direction": "asc"}],
            "limit": 10,
            "offset": 0
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        expected_order = ['low', 'med', 'high', 'critical']

        assert expected_order == [vuln['value']['severity'] for vuln in res.json['vulnerabilities']]

    def test_filter_by_creator_command_id(self,
                                          test_client,
                                          session,
                                          workspace,
                                          command_object_factory,
                                          empty_command_factory):

        command = empty_command_factory.create(workspace=workspace,
                                               tool="metasploit")
        session.commit()
        vulns_web = VulnerabilityWebFactory.create_batch(10, workspace=workspace, severity='high')
        vulns = VulnerabilityFactory.create_batch(100, workspace=workspace, severity='high')
        another_workspace = WorkspaceFactory.create()
        more_vulns = VulnerabilityFactory.create_batch(10, workspace=another_workspace, severity='high')
        session.add_all(more_vulns)
        session.add_all(vulns_web)
        session.add_all(vulns)
        session.commit()
        for vuln in vulns:
            command_object_factory.create(command=command,
                                          object_type='vulnerability',
                                          object_id=vuln.id,
                                          workspace=workspace)
        session.commit()

        query_filter = {
            "filters": [{"and": [
                {"name": "creator_command_id", "op": "==", "val": command.id}]
            }],
            "offset": 0,
            "limit": 40
        }

        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 100

    def test_add_evidence_with_description(self, test_client, session, workspace, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()

        file_contents = b'Testing attachment with description'
        data = {
            'file': (BytesIO(file_contents), 'testing_description.txt'),
            'csrf_token': csrf_token,
            'description': 'Attachment description'
        }

        res = test_client.post(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment',
            data=data,
            use_json_data=False
        )
        assert res.status_code == 200

        # Get vulnerability created
        res = test_client.get(f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment')
        assert res.status_code == 200
        attachments_json = res.json

        attachment = attachments_json['testing_description.txt']

        assert attachment['description'] == 'Attachment description'

    def test_patch_attachment_description(self, test_client, session, workspace, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()

        file_contents = b'Testing attachment with description'
        data = {
            'file': (BytesIO(file_contents), 'testing_description.txt'),
            'csrf_token': csrf_token,
            'description': 'Attachment description'
        }

        res = test_client.post(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment',
            data=data,
            use_json_data=False
        )
        assert res.status_code == 200

        patch_data = {'description': 'Updated attachment description'}
        res = test_client.patch(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment/testing_description.txt',
            json=patch_data,
        )

        assert res.status_code == 200

        updated_attachment = session.query(File).filter_by(
            object_type='vulnerability',
            object_id=vuln.id,
            filename='testing_description.txt'
        ).one()
        assert updated_attachment.description == 'Updated attachment description'

    def test_patch_attachment_description_bad_body(self, test_client, session, workspace, csrf_token):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add(vuln)
        session.commit()

        file_contents = b'Testing attachment with description'
        data = {
            'file': (BytesIO(file_contents), 'testing_description.txt'),
            'csrf_token': csrf_token,
            'description': 'Attachment description'
        }

        res = test_client.post(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment',
            data=data,
            use_json_data=False
        )
        assert res.status_code == 200

        patch_data = {'descriptions': 'Updated attachment description'}
        res = test_client.patch(
            f'/v3/ws/{workspace.name}/vulns/{vuln.id}/attachment/testing_description.txt',
            json=patch_data,
        )

        assert res.status_code == 400

    @pytest.mark.usefixtures('ignore_nplusone')
    @pytest.mark.parametrize("column", VALID_FILTER_VULN_COLUMNS)
    def test_custom_columns_with_filter(self, test_client, session, column):
        # Test that each valid vulnerability column can be used in filter requests
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        med_vulns = VulnerabilityFactory.create_batch(10,
                                                      workspace=workspace,
                                                      severity='medium'
                                                      )
        session.add_all(med_vulns)
        session.add(host)
        session.commit()

        # Construct filter query that specifies which column to return
        query_filter = {
            "filters": [{"name": "severity", "op": "eq", "val": "medium"}],
            "columns": [column],
        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        assert res.status_code == 200
        assert res.json['count'] == 10
        # Verify that the requested column is included in the response
        assert column in res.json['vulnerabilities'][0]["value"]

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_custom_columns_with_filter_invalid_column(self, test_client, session):
        # Test that using an invalid column name returns an error
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        med_vulns = VulnerabilityFactory.create_batch(10,
                                                      workspace=workspace,
                                                      severity='medium'
                                                      )
        session.add_all(med_vulns)
        session.add(host)
        session.commit()

        # Construct filter query with an invalid column name
        query_filter = {
            "filters": [{"name": "severity", "op": "eq", "val": "medium"}],
            "columns": ["invalid"],
        }
        res = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?q={json.dumps(query_filter)}'
        )
        # Should return 400 Bad Request when an invalid column is specified
        assert res.status_code == 400

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_export_csv_limited(self, test_client, session):
        workspace = WorkspaceFactory.create()
        host = HostFactory.create(workspace=workspace)
        med_vulns = VulnerabilityFactory.create_batch(10,
                                                      workspace=workspace,
                                                      severity='medium'
                                                      )
        session.add_all(med_vulns)
        session.add(host)
        session.commit()

        query_filter = {
            "filters": [{"name": "severity", "op": "eq", "val": "medium"}],
            "columns": VALID_FILTER_VULN_COLUMNS,
        }
        response = test_client.get(
            f'/v3/ws/{workspace.name}/vulns/filter?export_csv_limited=true&q={json.dumps(query_filter)}'
        )
        assert response.status_code == 200

        # Check content type and filename
        assert "text/csv" in response.content_type
        assert "attachment" in response.headers["Content-Disposition"]
        assert f"Faraday-SR-{workspace.name}.csv" in response.headers["Content-Disposition"]

        # Parse and verify CSV content
        csv_content = StringIO(response.data.decode('utf-8'))
        csv_reader = csv.DictReader(csv_content)
        rows = list(csv_reader)

        # Verify we have the expected number of rows
        assert len(rows) == 10

        # Verify headers are correct
        assert set(rows[0].keys()) == set(VALID_FILTER_VULN_COLUMNS)
