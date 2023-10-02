'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from datetime import date
import time
from urllib.parse import urljoin

import pytest
from posixpath import join

from faraday.server.models import Workspace, Scope, SeveritiesHistogram
from faraday.server.api.modules.workspaces import WorkspaceView
from tests.test_api_non_workspaced_base import ReadWriteAPITests, BulkDeleteTestsMixin
from tests import factories


vulnerabilities = [
    {
        'type': 'web',
        'status': 'open',
        'confirmed': True,
        'severity': 'critical',
        'count': 2
    },
    {
        'type': 'web',
        'status': 'risk-accepted',
        'confirmed': True,
        'severity': 'critical',
        'count': 2
    },
    {
        'type': 'std',
        'status': 're-opened',
        'confirmed': True,
        'severity': 'critical',
        'count': 1
    },
    {
        'type': 'std',
        'status': 'closed',
        'confirmed': True,
        'severity': 'critical',
        'count': 1
    },
    {
        'type': 'web',
        'status': 'open',
        'confirmed': False,
        'severity': 'critical',
        'count': 3
    },
    {
        'type': 'web',
        'status': 'risk-accepted',
        'confirmed': False,
        'severity': 'critical',
        'count': 0
    },
    {
        'type': 'std',
        'status': 're-opened',
        'confirmed': False,
        'severity': 'critical',
        'count': 2
    },
    {
        'type': 'std',
        'status': 'closed',
        'confirmed': False,
        'severity': 'critical',
        'count': 1,
    },
    {
        'type': 'web',
        'status': 'open',
        'confirmed': True,
        'severity': 'high',
        'count': 1,
    },
    {
        'type': 'std',
        'status': 're-opened',
        'confirmed': True,
        'severity': 'high',
        'count': 1,
    },
    {
        'type': 'web',
        'status': 'risk-accepted',
        'confirmed': True,
        'severity': 'medium',
        'count': 1,
    },
    {
        'type': 'web',
        'status': 'open',
        'confirmed': True,
        'severity': 'medium',
        'count': 1,
    },
    {
        'type': 'std',
        'status': 'open',
        'confirmed': True,
        'severity': 'low',
        'count': 1,
    },
    {
        'type': 'web',
        'status': 'open',
        'confirmed': True,
        'severity': 'low',
        'count': 1,
    },
    {
        'type': 'web',
        'status': 'open',
        'confirmed': True,
        'severity': 'informational',
        'count': 1,
    },
    {
        'type': 'std',
        'status': 'open',
        'confirmed': True,
        'severity': 'informational',
        'count': 1,
    },
    {
        'type': 'web',
        'status': 'closed',
        'confirmed': True,
        'severity': 'unclassified',
        'count': 1,
    },
    {
        'type': 'std',
        'status': 'closed',
        'confirmed': True,
        'severity': 'unclassified',
        'count': 2,
    },
]


class TestWorkspaceAPI(ReadWriteAPITests, BulkDeleteTestsMixin):
    model = Workspace
    factory = factories.WorkspaceFactory
    api_endpoint = 'ws'
    lookup_field = 'name'
    view_class = WorkspaceView
    patchable_fields = ['description']

    @pytest.fixture(autouse=True)
    def mock_envelope_list(self, monkeypatch):
        assert self.view_class is not None, 'You must define view_class ' \
                                            'in order to use ListTestsMixin or PaginationTestsMixin'

        def _envelope_list(_, objects, pagination_metadata=None):
            return objects

        monkeypatch.setattr(self.view_class, '_envelope_list', _envelope_list)

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_fixed_stats_in_workspace(self, session, test_client, vulnerability_factory, workspace_factory):
        ws = workspace_factory.create(name='myws')
        session.add(ws)
        session.commit()

        vulns = vulnerability_factory.create_batch(8, workspace=ws,
                                                   confirmed=False, status='open', severity='informational')

        vulns += vulnerability_factory.create_batch(3, workspace=ws,
                                                    confirmed=True, status='closed', severity='low')

        vulns += vulnerability_factory.create_batch(2, workspace=ws,
                                                    confirmed=True, status='re-opened', severity='low')

        vulns += vulnerability_factory.create_batch(1, workspace=ws,
                                                    confirmed=False, status='risk-accepted', severity='medium')

        vulns += vulnerability_factory.create_batch(5, workspace=ws,
                                                    confirmed=False, status='closed', severity='high')

        vulns += vulnerability_factory.create_batch(3, workspace=ws,
                                                    confirmed=False, status='open', severity='critical')

        vulns += vulnerability_factory.create_batch(3, workspace=ws,
                                                    confirmed=True, status='closed', severity='critical')
        session.add_all(vulns)
        session.commit()

        res = test_client.get(urljoin(self.url(ws), 'filter?q={"filters":[{"name": "name", "op":"eq", "val": "myws"}]}'))

        assert res.status_code == 200
        assert res.json[0]['stats']['opened_vulns'] == 14
        assert res.json[0]['stats']['closed_vulns'] == 11
        assert res.json[0]['stats']['info_vulns'] == 8
        assert res.json[0]['stats']['low_vulns'] == 5
        assert res.json[0]['stats']['medium_vulns'] == 1
        assert res.json[0]['stats']['high_vulns'] == 5
        assert res.json[0]['stats']['critical_vulns'] == 6
        assert res.json[0]['stats']['confirmed_vulns'] == 8

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_by_name(self, test_client):
        res = test_client.get(
            join(
                self.url(),
                f'filter?q={{"filters":[{{"name": "name", "op":"eq", "val": "{self.first_object.name}"}}]}}'
            )
        )
        assert res.status_code == 200
        assert len(res.json) == 1
        assert res.json[0]['name'] == self.first_object.name

    @pytest.mark.usefixtures('ignore_nplusone')
    def test_filter_restless_by_name_zero_results_found(self, test_client):
        res = test_client.get(
            join(
                self.url(),
                'filter?q={"filters":[{"name": "name", "op":"eq", "val": "thiswsdoesnotexist"}]}'
            )
        )
        assert res.status_code == 200
        assert len(res.json) == 0

    def test_filter_restless_by_description(self, test_client):
        self.first_object.description = "this is a new description"
        res = test_client.get(
            join(
                self.url(),
                f'filter?q={{"filters":[{{"name": "description", "op":"eq", "val": "{self.first_object.description}"}}'
                ']}'
            )
        )
        assert res.status_code == 200
        assert len(res.json) == 1
        assert res.json[0]['description'] == self.first_object.description

    def test_filter_restless_with_vulns_stats(self, test_client, vulnerability_factory,
                                              vulnerability_web_factory, session):

        vulns = vulnerability_factory.create_batch(8, workspace=self.first_object,
                                                   confirmed=False, status='open', severity='informational')

        vulns += vulnerability_factory.create_batch(3, workspace=self.first_object,
                                                    confirmed=True, status='closed', severity='critical')

        vulns += vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                    confirmed=True, status='open', severity='low')

        vulns += vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                        confirmed=True, status='open', severity='high')

        vulns += vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                        confirmed=True, status='open', severity='unclassified')

        vulns += vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                        confirmed=True, status='open', severity='medium')

        session.add_all(vulns)
        session.commit()

        self.first_object.description = "this is a new description"
        res = test_client.get(
            join(
                self.url(),
                f'filter?q={{"filters":[{{"name": "description", "op":"eq", "val": "{self.first_object.description}"}}'
                ']}'
            )
        )
        assert res.status_code == 200
        assert len(res.json) == 1

        assert res.json[0]['stats']['std_vulns'] == 11
        assert res.json[0]['stats']['web_vulns'] == 8
        assert res.json[0]['stats']['code_vulns'] == 0

        assert res.json[0]['description'] == self.first_object.description
        assert res.json[0]['stats']['total_vulns'] == 19
        assert res.json[0]['stats']['info_vulns'] == 8
        assert res.json[0]['stats']['critical_vulns'] == 3
        assert res.json[0]['stats']['low_vulns'] == 2
        assert res.json[0]['stats']['high_vulns'] == 2
        assert res.json[0]['stats']['medium_vulns'] == 2
        assert res.json[0]['stats']['unclassified_vulns'] == 2

    def test_host_count(self, host_factory, test_client, session):
        host_factory.create(workspace=self.first_object)
        session.commit()
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        assert res.json['stats']['hosts'] == 1

    @pytest.mark.parametrize('query', [
        {
            'params': {
                'confirmed': 'true',
                'only_opened': 'true'
            },
            'result': {
                'hosts': 5,
                'services': 5,
                'code_vulns': 0,
                'web_vulns': 9,
                'std_vulns': 4,
                'critical_vulns': 5,
                'high_vulns': 2,
                'info_vulns': 2,
                'low_vulns': 2,
                'medium_vulns': 2,
                'unclassified_vulns': 0,
                'opened_vulns': 8,
                're_opened_vulns': 2,
                'risk_accepted_vulns': 3,
                'closed_vulns': 0,
                'total_vulns': 13,
            }
        },
        {
            'params': {
                'confirmed': 'true',
                'only_opened': 'false'
            },
            'result': {
                'hosts': 5,
                'services': 5,
                'code_vulns': 0,
                'web_vulns': 10,
                'std_vulns': 7,
                'critical_vulns': 6,
                'high_vulns': 2,
                'info_vulns': 2,
                'low_vulns': 2,
                'medium_vulns': 2,
                'unclassified_vulns': 3,
                'opened_vulns': 8,
                're_opened_vulns': 2,
                'risk_accepted_vulns': 3,
                'closed_vulns': 4,
                'total_vulns': 17,
            }
        },
        {
            'params': {
                'confirmed': 'false',
                'only_opened': 'true'
            },
            'result': {
                'hosts': 5,
                'services': 5,
                'code_vulns': 0,
                'web_vulns': 3,
                'std_vulns': 2,
                'critical_vulns': 5,
                'high_vulns': 0,
                'info_vulns': 0,
                'low_vulns': 0,
                'medium_vulns': 0,
                'unclassified_vulns': 0,
                'opened_vulns': 3,
                're_opened_vulns': 2,
                'risk_accepted_vulns': 0,
                'closed_vulns': 0,
                'total_vulns': 5,
            }
        },
        {
            'params': {
                'confirmed': 'false',
                'only_opened': 'false'
            },
            'result': {
                'hosts': 5,
                'services': 5,
                'code_vulns': 0,
                'web_vulns': 3,
                'std_vulns': 3,
                'critical_vulns': 6,
                'high_vulns': 0,
                'info_vulns': 0,
                'low_vulns': 0,
                'medium_vulns': 0,
                'unclassified_vulns': 0,
                'opened_vulns': 3,
                're_opened_vulns': 2,
                'risk_accepted_vulns': 0,
                'closed_vulns': 1,
                'total_vulns': 6,
            }
        },
    ])
    def test_workspace_stats(self,
                             vulnerability_factory,
                             vulnerability_web_factory,
                             test_client,
                             session,
                             query):

        vulns = []
        for vulnerability in vulnerabilities:
            if vulnerability['type'] == 'web':
                vulns += vulnerability_web_factory.create_batch(vulnerability['count'],
                                                                workspace=self.first_object,
                                                                confirmed=vulnerability['confirmed'],
                                                                status=vulnerability['status'],
                                                                severity=vulnerability['severity'])
            else:
                vulns += vulnerability_factory.create_batch(vulnerability['count'],
                                                            workspace=self.first_object,
                                                            confirmed=vulnerability['confirmed'],
                                                            status=vulnerability['status'],
                                                            severity=vulnerability['severity'])
        session.add_all(vulns)
        session.commit()

        params = f'?confirmed={query["params"]["confirmed"]}&only_opened={query["params"]["only_opened"]}'

        res = test_client.get(urljoin(self.url(self.first_object), params))
        assert res.status_code == 200

        # Static fields
        # assert res.json['stats']['hosts'] == query['result']['hosts']
        # assert res.json['stats']['services'] == query['result']['services']

        # vulnerability types
        assert res.json['stats']['code_vulns'] == query['result']['code_vulns']
        assert res.json['stats']['web_vulns'] == query['result']['web_vulns']
        assert res.json['stats']['std_vulns'] == query['result']['std_vulns']

        # vulnerability by severity
        assert res.json['stats']['critical_vulns'] == query['result']['critical_vulns']
        assert res.json['stats']['high_vulns'] == query['result']['high_vulns']
        assert res.json['stats']['medium_vulns'] == query['result']['medium_vulns']
        assert res.json['stats']['low_vulns'] == query['result']['low_vulns']
        assert res.json['stats']['info_vulns'] == query['result']['info_vulns']
        assert res.json['stats']['unclassified_vulns'] == query['result']['unclassified_vulns']

        # vulnerability by status
        assert res.json['stats']['opened_vulns'] == query['result']['opened_vulns']
        assert res.json['stats']['re_opened_vulns'] == query['result']['re_opened_vulns']
        assert res.json['stats']['risk_accepted_vulns'] == query['result']['risk_accepted_vulns']
        assert res.json['stats']['closed_vulns'] == query['result']['closed_vulns']

        assert res.json['stats']['total_vulns'] == query['result']['total_vulns']

    @pytest.mark.skip_sql_dialect('sqlite')
    @pytest.mark.usefixtures('ignore_nplusone')
    def test_histogram(self,
                        vulnerability_factory,
                        vulnerability_web_factory,
                        second_workspace,
                        test_client,
                        session):

        session.query(SeveritiesHistogram).delete()
        session.commit()

        vulns = vulnerability_factory.create_batch(8, workspace=self.first_object,
                                                   confirmed=False, status='open', severity='critical')

        vulns += vulnerability_factory.create_batch(3, workspace=self.first_object,
                                                    confirmed=True, status='open', severity='high')

        vulns += vulnerability_web_factory.create_batch(2, workspace=second_workspace,
                                                    confirmed=True, status='open', severity='medium')

        vulns += vulnerability_web_factory.create_batch(2, workspace=second_workspace,
                                                    confirmed=True, status='open', severity='low')

        session.add_all(vulns)
        session.commit()
        res = test_client.get('/v3/ws?histogram=true')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 20
        ws_histogram = firs_ws[0]
        for ws_date in ws_histogram:
            if ws_date['date'] == date.today().strftime("%Y-%m-%d"):
                assert ws_date['medium'] == 0
                assert ws_date['high'] == 3
                assert ws_date['critical'] == 8
                assert ws_date['confirmed'] == 3
            else:
                assert ws_date['medium'] == 0
                assert ws_date['high'] == 0
                assert ws_date['critical'] == 0
                assert ws_date['confirmed'] == 0

        second_ws = [ws['histogram'] for ws in res.json if ws['name'] == second_workspace.name]
        assert len(second_ws[0]) == 20
        ws_histogram = second_ws[0]
        for ws_date in ws_histogram:
            if ws_date['date'] == date.today().strftime("%Y-%m-%d"):
                assert ws_date['medium'] == 2
                assert ws_date['high'] == 0
                assert ws_date['critical'] == 0
                assert ws_date['confirmed'] == 2
            else:
                assert ws_date['medium'] == 0
                assert ws_date['high'] == 0
                assert ws_date['critical'] == 0
                assert ws_date['confirmed'] == 0

        res = test_client.get('/v3/ws?histogram=True&histogram_days=a')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 20

        res = test_client.get('/v3/ws?histogram=true&histogram_days=[asdf, "adsf"]')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 20

        res = test_client.get('/v3/ws?histogram=true&histogram_days=[asdf, "adsf"]')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 20

        res = test_client.get('/v3/ws?histogram=true&histogram_days=5')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 5

        res = test_client.get('/v3/ws?histogram=true&histogram_days=365')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 365

        res = test_client.get('/v3/ws?histogram=asdf&histogram_days=365')
        assert res.status_code == 200
        for ws in res.json:
            assert 'histogram' not in ws

    def test_create_fails_with_valid_duration(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        start_date = int(time.time()) * 1000
        end_date = start_date + 86400000
        duration = {'start_date': start_date, 'end_date': end_date}
        raw_data = {'name': 'somethingdarkside', 'duration': duration}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert workspace_count_previous + 1 == session.query(Workspace).count()
        assert res.json['duration']['start_date'] == start_date
        assert res.json['duration']['end_date'] == end_date

    def test_create_succeeds_with_mayus(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        raw_data = {'name': 'sWtr'}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert workspace_count_previous + 1 == session.query(Workspace).count()

    def test_create_fails_with_special_character(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        raw_data = {'name': '$wtr'}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    def test_create_with_initial_number(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        raw_data = {'name': '2$wtr'}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert workspace_count_previous + 1 == session.query(Workspace).count()

    def test_create_fails_with_invalid_duration_start_type(self,
                                                           session,
                                                           test_client):
        workspace_count_previous = session.query(Workspace).count()
        start_date = 'this should clearly fail'
        duration = {'start_date': start_date, 'end_date': 86400000}
        raw_data = {'name': 'somethingdarkside', 'duration': duration}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    @pytest.mark.xfail(reason="Filter not implemented yet")
    def test_create_fails_with_invalid_duration_start_after_end(self,
                                                                session,
                                                                test_client):
        workspace_count_previous = session.query(Workspace).count()
        start_date = int(time.time()) * 1000
        duration = {'start_date': start_date, 'end_date': start_date - 86400000}
        raw_data = {'name': 'somethingdarkside', 'duration': duration}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    def test_create_fails_with_forward_slash(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        raw_data = {'name': 'swtr/'}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    def test_create_with_description(self, session, test_client):
        description = 'darkside'
        raw_data = {'name': 'something', 'description': description}
        workspace_count_previous = session.query(Workspace).count()
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert workspace_count_previous + 1 == session.query(Workspace).count()
        assert res.json['description'] == description

    @pytest.mark.parametrize("stat_name", [
        'credentials', 'services', 'web_vulns', 'code_vulns', 'std_vulns',
        'total_vulns'
    ])
    def test_create_stat_is_zero(self, test_client, stat_name):
        raw_data = {'name': 'something', 'description': ''}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert res.json['stats'][stat_name] == 0

    def test_update_stats(self, workspace, session, test_client,
                          vulnerability_factory,
                          vulnerability_web_factory):
        vulns = vulnerability_factory.create_batch(10, workspace=workspace)
        vulns += vulnerability_web_factory.create_batch(5, workspace=workspace)
        session.add_all(vulns)
        session.commit()
        raw_data = {'name': 'something', 'description': ''}
        res = test_client.put(self.url(obj=workspace), data=raw_data)
        assert res.status_code == 200
        assert res.json['stats']['web_vulns'] == 5
        assert res.json['stats']['std_vulns'] == 10
        assert res.json['stats']['total_vulns'] == 15

    def test_create_with_scope(self, session, test_client):
        desired_scope = [
            'www.google.com',
            '127.0.0.1'
        ]
        raw_data = {'name': 'something', 'description': 'test',
                    'scope': desired_scope}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 201
        assert set(res.json['scope']) == set(desired_scope)
        workspace = Workspace.query.get(res.json['id'])
        assert {s.name for s in workspace.scope} == set(desired_scope)

    def test_update_with_scope(self, session, test_client, workspace):
        session.add(Scope(name='test.com', workspace=workspace))
        session.add(Scope(name='www.google.com', workspace=workspace))
        desired_scope = [
            'www.google.com',
            '127.0.0.1'
        ]
        raw_data = {'name': 'something', 'description': 'test',
                    'scope': desired_scope}
        res = test_client.put(self.url(obj=workspace), data=raw_data)
        assert res.status_code == 200
        assert set(res.json['scope']) == set(desired_scope)
        assert {s.name for s in workspace.scope} == set(desired_scope)

    @pytest.mark.skip_sql_dialect('sqlite')
    def test_list_retrieves_all_items_from(self, test_client, logged_user):
        super().test_list_retrieves_all_items_from(test_client, logged_user)

    def test_workspace_activation(self, test_client, workspace, session):
        workspace.active = False
        session.add(workspace)
        session.commit()
        res = test_client.patch(self.url(workspace), data={'active': True})
        assert res.status_code == 200

        res = test_client.get(self.url(workspace))
        active = res.json.get('active')
        assert active

        active_query = session.query(Workspace).filter_by(id=workspace.id).first().active
        assert active_query

    def test_workspace_deactivation(self, test_client, workspace, session):
        workspace.active = True
        session.add(workspace)
        session.commit()
        res = test_client.patch(self.url(workspace), data={'active': False})
        assert res.status_code == 200

        res = test_client.get(self.url(workspace))
        active = res.json.get('active')
        assert not active

        active_query = session.query(Workspace).filter_by(id=workspace.id).first().active
        assert not active_query

    def test_create_fails_with_start_date_greater_than_end_date(self,
                                                           session,
                                                           test_client):
        workspace_count_previous = session.query(Workspace).count()
        duration = {'start_date': 1563638577, 'end_date': 1563538577}
        raw_data = {'name': 'somethingdarkside', 'duration': duration}
        res = test_client.post(self.url(), data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()
