'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import time
import pytest

from server.models import Workspace, Scope
from server.api.modules.workspaces import WorkspaceView
from test_cases.conftest import ignore_nplusone
from test_cases.test_api_non_workspaced_base import ReadWriteAPITests
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


    def test_vuln_count(self,
                        vulnerability_factory,
                        test_client,
                        session):
        vulns = vulnerability_factory.create_batch(8, workspace=self.first_object,
                                                   confirmed=False)
        vulns += vulnerability_factory.create_batch(5, workspace=self.first_object,
                                                    confirmed=True)
        session.add_all(vulns)
        session.commit()
        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200
        assert res.json['stats']['total_vulns'] == 13

    @pytest.mark.parametrize('querystring', [
        '?confirmed=1',
        '?confirmed=true'
    ])

    def test_vuln_count_confirmed(self,
                                  vulnerability_factory,
                                  test_client,
                                  session,
                                  querystring):
        vulns = vulnerability_factory.create_batch(8, workspace=self.first_object,
                                                   confirmed=False)
        vulns += vulnerability_factory.create_batch(5, workspace=self.first_object,
                                                    confirmed=True)
        session.add_all(vulns)
        session.commit()
        res = test_client.get(self.url(self.first_object) + querystring)
        assert res.status_code == 200
        assert res.json['stats']['total_vulns'] == 5

    @pytest.mark.parametrize('querystring', [
        '?confirmed=0',
        '?confirmed=false'
    ])

    def test_vuln_count_confirmed(self,
                                  vulnerability_factory,
                                  test_client,
                                  session,
                                  querystring):
        vulns = vulnerability_factory.create_batch(8, workspace=self.first_object,
                                                   confirmed=False)
        vulns += vulnerability_factory.create_batch(5, workspace=self.first_object,
                                                    confirmed=True)
        session.add_all(vulns)
        session.commit()
        res = test_client.get(self.url(self.first_object) + querystring)
        assert res.status_code == 200
        assert res.json['stats']['total_vulns'] == 8

    def test_create_fails_with_valid_duration(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        start_date = int(time.time())*1000
        end_date = start_date+86400000
        duration = {'start_date': start_date, 'end_date': end_date}
        raw_data = {'name': 'somethingdarkside', 'duration': duration}
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 201
        assert workspace_count_previous + 1 == session.query(Workspace).count()
        assert res.json['duration']['start_date'] == start_date
        assert res.json['duration']['end_date'] == end_date

    def test_create_fails_with_mayus(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        raw_data = {'name': 'sWtr'}
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    def test_create_fails_with_special_character(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        raw_data = {'name': '$wtr'}
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    def test_create_with_initial_number(self, session, test_client):
        workspace_count_previous = session.query(Workspace).count()
        raw_data = {'name': '2$wtr'}
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 201
        assert workspace_count_previous + 1 == session.query(Workspace).count()

    def test_create_fails_with_invalid_duration_start_type(self,
                                                           session,
                                                           test_client):
        workspace_count_previous = session.query(Workspace).count()
        start_date = 'this should clearly fail'
        duration = {'start_date': start_date, 'end_date': 86400000}
        raw_data = {'name': 'somethingdarkside', 'duration': duration}
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    @pytest.mark.xfail(reason="Filter not implemented yet")
    def test_create_fails_with_invalid_duration_start_after_end(self,
                                                                session,
                                                                test_client):
        workspace_count_previous = session.query(Workspace).count()
        start_date = int(time.time())*1000
        duration = {'start_date': start_date, 'end_date': start_date-86400000}
        raw_data = {'name': 'somethingdarkside', 'duration': duration}
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 400
        assert workspace_count_previous == session.query(Workspace).count()

    def test_create_with_description(self, session, test_client):
        description = 'darkside'
        raw_data = {'name': 'something', 'description': description}
        workspace_count_previous = session.query(Workspace).count()
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 201
        assert workspace_count_previous + 1 == session.query(Workspace).count()
        assert res.json['description'] == description

    @pytest.mark.parametrize("stat_name", [
        'credentials', 'services', 'web_vulns', 'code_vulns', 'std_vulns',
        'total_vulns'
    ])
    def test_create_stat_is_zero(self, test_client, stat_name):
        raw_data = {'name': 'something', 'description': ''}
        res = test_client.post('/v2/ws/', data=raw_data)
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
        res = test_client.put('/v2/ws/{}/'.format(workspace.name),
                              data=raw_data)
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
        res = test_client.post('/v2/ws/', data=raw_data)
        assert res.status_code == 201
        assert set(res.json['scope']) == set(desired_scope)
        workspace = Workspace.query.get(res.json['id'])
        assert set(s.name for s in workspace.scope) == set(desired_scope)

    def test_update_with_scope(self, session, test_client, workspace):
        session.add(Scope(name='test.com', workspace=workspace))
        session.add(Scope(name='www.google.com', workspace=workspace))
        desired_scope = [
            'www.google.com',
            '127.0.0.1'
        ]
        raw_data = {'name': 'something', 'description': 'test',
                    'scope': desired_scope}
        res = test_client.put('/v2/ws/{}/'.format(workspace.name),
                              data=raw_data)
        assert res.status_code == 200
        assert set(res.json['scope']) == set(desired_scope)
        assert set(s.name for s in workspace.scope) == set(desired_scope)

    @ignore_nplusone
    def test_list_retrieves_all_items_from(self, test_client):
        super(TestWorkspaceAPI, self).test_list_retrieves_all_items_from(test_client)

