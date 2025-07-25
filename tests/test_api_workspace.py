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
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.tasks import update_host_stats

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

    def test_workspace_update_date(self, session, workspace_factory):
        from faraday.server.debouncer import Debouncer

        raw_data_1 = {'name': 'test_update_1'}
        raw_data_2 = {'name': 'test_update_2'}
        raw_data_3 = {'name': 'test_update_3'}

        ws1 = workspace_factory.create(public=False, name='test_update_1')
        session.commit()
        ws2 = workspace_factory.create(public=False, name='test_update_2')
        session.commit()
        ws3 = workspace_factory.create(public=False, name='test_update_3')
        session.commit()

        debouncer = Debouncer(wait=5)

        for i in range(1, 50):
            debounce_workspace_update(raw_data_1['name'], debouncer)
            debounce_workspace_update(raw_data_2['name'], debouncer)
            debounce_workspace_update(raw_data_3['name'], debouncer)
            debounce_workspace_update(raw_data_1['name'], debouncer)

        assert len(debouncer.actions) == 1
        time.sleep(7)
        test_update2 = session.query(Workspace).filter(Workspace.name == raw_data_2['name']).first()
        test_update3 = session.query(Workspace).filter(Workspace.name == raw_data_3['name']).first()
        test_update1 = session.query(Workspace).filter(Workspace.name == raw_data_1['name']).first()

        assert test_update2.update_date < test_update3.update_date < test_update1.update_date

    def test_vuln_counts(self, session, test_client, vulnerability_factory, workspace_factory, host_factory,
                         service_factory):
        from faraday.server.debouncer import Debouncer
        ws = workspace_factory.create(name='myws')
        session.add(ws)
        session.commit()
        host = host_factory.create(workspace=ws)
        session.add(host)
        session.commit()
        host2 = host_factory.create(workspace=ws)
        session.add(host2)
        session.commit()
        service = service_factory.create(workspace=ws, host=host2)
        session.add(service)
        session.commit()
        host3 = host_factory.create(workspace=ws)
        session.add(host3)
        session.commit()
        service2 = service_factory.create(workspace=ws, host=host3)
        session.add(service2)
        session.commit()

        vulns = vulnerability_factory.create_batch(8, workspace=ws, type='vulnerability_web',
                                                   confirmed=False, status='open', severity='informational', host=host,
                                                   service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(3, workspace=ws, type='vulnerability_code',
                                                   confirmed=True, status='closed', severity='low', host=None,
                                                   service=service)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws,
                                                   confirmed=True, status='re-opened', severity='low', host=host,
                                                   service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(1, workspace=ws,
                                                   confirmed=False, status='risk-accepted', severity='medium',
                                                   host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(5, workspace=ws,
                                                   confirmed=False, status='closed', severity='high', host=None,
                                                   service=service2)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(3, workspace=ws,
                                                   confirmed=False, status='open', severity='critical', host=host,
                                                   service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(3, workspace=ws, type='vulnerability_web',
                                                   confirmed=True, status='closed', severity='critical', host=host,
                                                   service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws,
                                                   confirmed=True, status='open', severity='unclassified', host=host,
                                                   service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(1, workspace=ws,
                                                   confirmed=True, status='risk-accepted', severity='medium',
                                                   host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws,
                                                   confirmed=True, status='re-opened', severity='high',
                                                   host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws,
                                                   confirmed=True, status='closed', severity='informational',
                                                   host=host2, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws, type='vulnerability_web',
                                                   confirmed=True, status='open', severity='critical', host=host,
                                                   service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(1, workspace=ws, type='vulnerability_code',
                                                   confirmed=False, status='open', severity='low', host=None,
                                                   service=service)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws, type='vulnerability_code',
                                                   confirmed=True, status='open', severity='medium', host=None,
                                                   service=service)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws, type='vulnerability_code',
                                                   confirmed=True, status='open', severity='informational', host=None,
                                                   service=service)
        session.add_all(vulns)
        session.commit()

        debouncer = Debouncer(wait=1)
        update_host_stats([host.id, host2.id], [service.id, service2.id], workspace_name=ws.name, debouncer=debouncer)
        time.sleep(3)

        ws = session.query(Workspace).filter(Workspace.name == 'myws').first()

        # Vuln hosts

        assert ws.host_confirmed_count == 2
        assert ws.host_notclosed_count == 2
        assert ws.host_notclosed_confirmed_count == 2

        # Vuln services

        assert ws.service_confirmed_count == 1
        assert ws.service_notclosed_count == 1
        assert ws.service_notclosed_confirmed_count == 1

        #  Total vulns by type

        assert ws.vulnerability_web_count == 13
        assert ws.vulnerability_code_count == 8
        assert ws.vulnerability_standard_count == 18

        #  Total vulns by status

        assert ws.vulnerability_open_count == 24
        assert ws.vulnerability_re_opened_count == 4
        assert ws.vulnerability_risk_accepted_count == 2
        assert ws.vulnerability_closed_count == 15

        #  Total confirmed vulns and total vulns

        assert ws.vulnerability_confirmed_count == 21
        assert ws.vulnerability_notclosed_count == 24
        assert ws.vulnerability_notclosed_confirmed_count == 12
        assert ws.vulnerability_total_count == 39

        #  Total vulns by severity

        assert ws.vulnerability_informational_count == 12
        assert ws.vulnerability_low_count == 6
        assert ws.vulnerability_medium_count == 4
        assert ws.vulnerability_high_count == 7
        assert ws.vulnerability_critical_count == 8
        assert ws.vulnerability_unclassified_count == 2

        #  Confirmed vulns by type

        assert ws.vulnerability_web_confirmed_count == 5
        assert ws.vulnerability_code_confirmed_count == 7
        assert ws.vulnerability_standard_confirmed_count == 9

        #  Confirmed vulns by status

        assert ws.vulnerability_open_confirmed_count == 12
        assert ws.vulnerability_re_opened_confirmed_count == 4
        assert ws.vulnerability_risk_accepted_confirmed_count == 1
        assert ws.vulnerability_closed_confirmed_count == 9

        #  Confirmed vulns by severity

        assert ws.vulnerability_high_confirmed_count == 2
        assert ws.vulnerability_critical_confirmed_count == 5
        assert ws.vulnerability_medium_confirmed_count == 3
        assert ws.vulnerability_low_confirmed_count == 5
        assert ws.vulnerability_informational_confirmed_count == 4
        assert ws.vulnerability_unclassified_confirmed_count == 2

        #  Not closed by type

        assert ws.vulnerability_web_notclosed_count == 10
        assert ws.vulnerability_code_notclosed_count == 5
        assert ws.vulnerability_standard_notclosed_count == 9

        #  Not closed by severity

        assert ws.vulnerability_high_notclosed_count == 2
        assert ws.vulnerability_critical_notclosed_count == 5
        assert ws.vulnerability_medium_notclosed_count == 2
        assert ws.vulnerability_low_notclosed_count == 3
        assert ws.vulnerability_informational_notclosed_count == 10
        assert ws.vulnerability_unclassified_notclosed_count == 2

        #  Confirmed and not closed by vuln type:

        assert ws.vulnerability_web_notclosed_confirmed_count == 2
        assert ws.vulnerability_code_notclosed_confirmed_count == 4
        assert ws.vulnerability_standard_notclosed_confirmed_count == 6

        # Confirmed and not closed by severity:

        assert ws.vulnerability_high_notclosed_confirmed_count == 2
        assert ws.vulnerability_critical_notclosed_confirmed_count == 2
        assert ws.vulnerability_medium_notclosed_confirmed_count == 2
        assert ws.vulnerability_low_notclosed_confirmed_count == 2
        assert ws.vulnerability_informational_notclosed_confirmed_count == 2
        assert ws.vulnerability_unclassified_notclosed_confirmed_count == 2

        # Service deletion
        session.delete(service2)
        session.commit()
        update_host_stats([host.id, host2.id, host3.id], [service.id], workspace_name=ws.name, debouncer=debouncer)
        time.sleep(3)

        ws = session.query(Workspace).filter(Workspace.name == 'myws').first()

        # After service2 deletion, its related vulnerabilities should be gone

        # Vuln hosts

        assert ws.host_confirmed_count == 2
        assert ws.host_notclosed_count == 2
        assert ws.host_notclosed_confirmed_count == 2

        # Vuln services

        assert ws.service_confirmed_count == 1
        assert ws.service_notclosed_count == 1
        assert ws.service_notclosed_confirmed_count == 1

        #  Total vulns by type

        assert ws.vulnerability_web_count == 13
        assert ws.vulnerability_code_count == 8
        assert ws.vulnerability_standard_count == 13

        #  Total vulns by status

        assert ws.vulnerability_open_count == 24
        assert ws.vulnerability_re_opened_count == 4
        assert ws.vulnerability_risk_accepted_count == 2
        assert ws.vulnerability_closed_count == 10  # 15 - 5 from service2

        #  Total vulns by severity

        assert ws.vulnerability_informational_count == 12
        assert ws.vulnerability_low_count == 6
        assert ws.vulnerability_medium_count == 4
        assert ws.vulnerability_high_count == 2  # 7 - 2 from service
        assert ws.vulnerability_critical_count == 8
        assert ws.vulnerability_unclassified_count == 2

        #  Total confirmed vulns and total vulns

        assert ws.vulnerability_confirmed_count == 21
        assert ws.vulnerability_notclosed_count == 24
        assert ws.vulnerability_notclosed_confirmed_count == 12
        assert ws.vulnerability_total_count == 34

        #  Confirmed vulns by type

        assert ws.vulnerability_web_confirmed_count == 5
        assert ws.vulnerability_code_confirmed_count == 7
        assert ws.vulnerability_standard_confirmed_count == 9

        #  Confirmed vulns by status

        assert ws.vulnerability_open_confirmed_count == 12
        assert ws.vulnerability_re_opened_confirmed_count == 4
        assert ws.vulnerability_risk_accepted_confirmed_count == 1
        assert ws.vulnerability_closed_confirmed_count == 9

        #  Confirmed vulns by severity

        assert ws.vulnerability_high_confirmed_count == 2
        assert ws.vulnerability_critical_confirmed_count == 5
        assert ws.vulnerability_medium_confirmed_count == 3
        assert ws.vulnerability_low_confirmed_count == 5
        assert ws.vulnerability_informational_confirmed_count == 4
        assert ws.vulnerability_unclassified_confirmed_count == 2

        #  Not closed by type

        assert ws.vulnerability_web_notclosed_count == 10
        assert ws.vulnerability_code_notclosed_count == 5
        assert ws.vulnerability_standard_notclosed_count == 9

        #  Not closed by severity

        assert ws.vulnerability_high_notclosed_count == 2
        assert ws.vulnerability_critical_notclosed_count == 5
        assert ws.vulnerability_medium_notclosed_count == 2
        assert ws.vulnerability_low_notclosed_count == 3
        assert ws.vulnerability_informational_notclosed_count == 10
        assert ws.vulnerability_unclassified_notclosed_count == 2

        #  Confirmed and not closed by vuln type:

        assert ws.vulnerability_web_notclosed_confirmed_count == 2
        assert ws.vulnerability_code_notclosed_confirmed_count == 4
        assert ws.vulnerability_standard_notclosed_confirmed_count == 6

        # Confirmed and not closed by severity:

        assert ws.vulnerability_high_notclosed_confirmed_count == 2
        assert ws.vulnerability_critical_notclosed_confirmed_count == 2
        assert ws.vulnerability_medium_notclosed_confirmed_count == 2
        assert ws.vulnerability_low_notclosed_confirmed_count == 2
        assert ws.vulnerability_informational_notclosed_confirmed_count == 2
        assert ws.vulnerability_unclassified_notclosed_confirmed_count == 2

        # Host deletion
        session.delete(host2)
        session.commit()
        update_host_stats([host.id, host3.id], [], workspace_name=ws.name, debouncer=debouncer)
        time.sleep(3)

        ws = session.query(Workspace).filter(Workspace.name == 'myws').first()

        # After host2 deletion, its related service and vulnerabilities should be gone

        # Vuln hosts

        assert ws.host_confirmed_count == 1  # 2 - 1 (host2)
        assert ws.host_notclosed_count == 1  # 2 - 1
        assert ws.host_notclosed_confirmed_count == 1  # 2 - 1

        # Vuln services

        assert ws.service_confirmed_count == 0  # All services gone
        assert ws.service_notclosed_count == 0  # All services gone
        assert ws.service_notclosed_confirmed_count == 0  # All services gone

        #  Total vulns by type

        assert ws.vulnerability_web_count == 13
        assert ws.vulnerability_code_count == 0  # 8 - 8 from service
        assert ws.vulnerability_standard_count == 11  # 13 - 2 from host2

        #  Total vulns by status

        assert ws.vulnerability_open_count == 19  # 24 -5 from service
        assert ws.vulnerability_re_opened_count == 4
        assert ws.vulnerability_risk_accepted_count == 2
        assert ws.vulnerability_closed_count == 5  # 10 -2 from host2 and -3 from service

        #  Total vulns by severity

        assert ws.vulnerability_informational_count == 8  # 12 -2 from service and -2 from host2
        assert ws.vulnerability_low_count == 2  # 6 -4 from service
        assert ws.vulnerability_medium_count == 2  # 4 -2 from service
        assert ws.vulnerability_high_count == 2
        assert ws.vulnerability_critical_count == 8
        assert ws.vulnerability_unclassified_count == 2

        #  Total confirmed vulns and total vulns

        assert ws.vulnerability_confirmed_count == 12  # 21 - 2 from host -7 from service
        assert ws.vulnerability_notclosed_count == 19  # 24 - 5 from service
        assert ws.vulnerability_notclosed_confirmed_count == 8  # 12 - 4 from service
        assert ws.vulnerability_total_count == 24  # 34 - 2 (vulns of host2) -8 (vulns of service which was related to host2)

        #  Confirmed vulns by type

        assert ws.vulnerability_web_confirmed_count == 5
        assert ws.vulnerability_code_confirmed_count == 0  # 7 -7 from service
        assert ws.vulnerability_standard_confirmed_count == 7  # 9 - 2 from host2

        #  Confirmed vulns by status

        assert ws.vulnerability_open_confirmed_count == 8  # 12 -4 from service
        assert ws.vulnerability_re_opened_confirmed_count == 4
        assert ws.vulnerability_risk_accepted_confirmed_count == 1
        assert ws.vulnerability_closed_confirmed_count == 4  # 9 -2 from host2 and -3 from service

        #  Confirmed vulns by severity

        assert ws.vulnerability_high_confirmed_count == 2
        assert ws.vulnerability_critical_confirmed_count == 5
        assert ws.vulnerability_medium_confirmed_count == 1  # 3 -2 from service
        assert ws.vulnerability_low_confirmed_count == 2  # 5 -3 from service
        assert ws.vulnerability_informational_confirmed_count == 0  # 4 -2 from service -2 from host2
        assert ws.vulnerability_unclassified_confirmed_count == 2

        #  Not closed by type

        assert ws.vulnerability_web_notclosed_count == 10
        assert ws.vulnerability_code_notclosed_count == 0  # 5 -5 from service
        assert ws.vulnerability_standard_notclosed_count == 9

        #  Not closed by severity

        assert ws.vulnerability_high_notclosed_count == 2
        assert ws.vulnerability_critical_notclosed_count == 5
        assert ws.vulnerability_medium_notclosed_count == 0  # 2 -2 from service
        assert ws.vulnerability_low_notclosed_count == 2  # 3 -1 from service
        assert ws.vulnerability_informational_notclosed_count == 8  # 10 -2 from service
        assert ws.vulnerability_unclassified_notclosed_count == 2

        #  Confirmed and not closed by vuln type:

        assert ws.vulnerability_web_notclosed_confirmed_count == 2
        assert ws.vulnerability_code_notclosed_confirmed_count == 0  # 4 -4 from service
        assert ws.vulnerability_standard_notclosed_confirmed_count == 6

        # Confirmed and not closed by severity:

        assert ws.vulnerability_high_notclosed_confirmed_count == 2
        assert ws.vulnerability_critical_notclosed_confirmed_count == 2
        assert ws.vulnerability_medium_notclosed_confirmed_count == 0  # 2 -2 from service
        assert ws.vulnerability_low_notclosed_confirmed_count == 2
        assert ws.vulnerability_informational_notclosed_confirmed_count == 0  # 2 -2 from service
        assert ws.vulnerability_unclassified_notclosed_confirmed_count == 2

    def test_filter_restless_fixed_stats_in_workspace(self, session, test_client, vulnerability_factory, workspace_factory, host_factory):
        from faraday.server.debouncer import Debouncer
        ws = workspace_factory.create(name='myws')
        session.add(ws)
        session.commit()
        host = host_factory.create(workspace=ws)
        session.add(host)
        session.commit()

        vulns = vulnerability_factory.create_batch(8, workspace=ws,
                                                   confirmed=False, status='open', severity='informational', host=host, service=None)
        session.add_all(vulns)
        session.commit()

        vulns = vulnerability_factory.create_batch(3, workspace=ws,
                                                    confirmed=True, status='closed', severity='low', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(2, workspace=ws,
                                                    confirmed=True, status='re-opened', severity='low', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(1, workspace=ws,
                                                    confirmed=False, status='risk-accepted', severity='medium', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(5, workspace=ws,
                                                    confirmed=False, status='closed', severity='high', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(3, workspace=ws,
                                                    confirmed=False, status='open', severity='critical', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(3, workspace=ws,
                                                    confirmed=True, status='closed', severity='critical', host=host, service=None)
        session.add_all(vulns)
        session.commit()

        debouncer = Debouncer(wait=1)

        update_host_stats([host.id], [], workspace_name=ws.name, debouncer=debouncer)

        time.sleep(3)

        res = test_client.get(urljoin(self.url(ws), 'filter?q={"filters":[{"name": "name", "op":"eq", "val": "myws"}]}'))
        print(res.data)

        assert res.status_code == 200
        assert res.json['rows'][0]['stats']['closed_vulns'] == 12
        assert res.json['rows'][0]['stats']['opened_vulns'] == 13
        assert res.json['rows'][0]['stats']['info_vulns'] == 8
        assert res.json['rows'][0]['stats']['low_vulns'] == 5
        assert res.json['rows'][0]['stats']['medium_vulns'] == 1
        assert res.json['rows'][0]['stats']['high_vulns'] == 5
        assert res.json['rows'][0]['stats']['critical_vulns'] == 6
        assert res.json['rows'][0]['stats']['confirmed_vulns'] == 8

    def test_filter_restless_by_name(self, test_client):
        res = test_client.get(
            join(
                self.url(),
                f'filter?q={{"filters":[{{"name": "name", "op":"eq", "val": "{self.first_object.name}"}}]}}'
            )
        )
        assert res.status_code == 200
        assert res.json['count'] == 1
        assert res.json['rows'][0]['name'] == self.first_object.name

    def test_filter_restless_by_name_zero_results_found(self, test_client):
        res = test_client.get(
            join(
                self.url(),
                'filter?q={"filters":[{"name": "name", "op":"eq", "val": "thiswsdoesnotexist"}]}'
            )
        )
        assert res.status_code == 200
        assert res.json['count'] == 0

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
        assert res.json['count'] == 1
        assert res.json['rows'][0]['description'] == self.first_object.description

    def test_filter_restless_with_vulns_stats(self, test_client, vulnerability_factory,
                                              vulnerability_web_factory, host_factory, session):
        from faraday.server.debouncer import Debouncer
        host = host_factory.create(workspace=self.first_object)
        session.add(host)
        session.commit()
        vulns = vulnerability_factory.create_batch(8, workspace=self.first_object,
                                                   confirmed=False, status='open', severity='informational', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_factory.create_batch(3, workspace=self.first_object,
                                                    confirmed=True, status='closed', severity='critical', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                    confirmed=True, status='open', severity='low', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                        confirmed=True, status='open', severity='high', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                        confirmed=True, status='open', severity='unclassified', host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_web_factory.create_batch(2, workspace=self.first_object,
                                                        confirmed=True, status='open', severity='medium', host=host, service=None)

        session.add_all(vulns)
        session.commit()

        self.first_object.description = "this is a new description"
        debouncer = Debouncer(wait=1)
        update_host_stats([host.id], [], workspace_name=self.first_object.name, debouncer=debouncer)
        time.sleep(3)
        res = test_client.get(
            join(
                self.url(),
                f'filter?q={{"filters":[{{"name": "description", "op":"eq", "val": "{self.first_object.description}"}}'
                ']}'
            )
        )
        assert res.status_code == 200
        assert res.json['count'] == 1

        assert res.json['rows'][0]['stats']['std_vulns'] == 11
        assert res.json['rows'][0]['stats']['web_vulns'] == 8
        assert res.json['rows'][0]['stats']['code_vulns'] == 0

        assert res.json['rows'][0]['description'] == self.first_object.description
        assert res.json['rows'][0]['stats']['total_vulns'] == 19
        assert res.json['rows'][0]['stats']['info_vulns'] == 8
        assert res.json['rows'][0]['stats']['critical_vulns'] == 3
        assert res.json['rows'][0]['stats']['low_vulns'] == 2
        assert res.json['rows'][0]['stats']['high_vulns'] == 2
        assert res.json['rows'][0]['stats']['medium_vulns'] == 2
        assert res.json['rows'][0]['stats']['unclassified_vulns'] == 2

    def test_host_count(self, host_factory, test_client, session):
        from faraday.server.debouncer import update_workspace_host_count

        host_factory.create(workspace=self.first_object)
        session.commit()
        update_workspace_host_count(workspace_id=self.first_object.id)
        session.add(self.first_object)
        session.refresh(self.first_object)
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
                'web_vulns': 6,
                'std_vulns': 4,
                'critical_vulns': 3,
                'high_vulns': 2,
                'info_vulns': 2,
                'low_vulns': 2,
                'medium_vulns': 1,
                'unclassified_vulns': 0,
                'opened_vulns': 10,
                're_opened_vulns': 2,
                'risk_accepted_vulns': 3,
                'closed_vulns': 7,
                'notclosed_confirmed_vulns': 10,
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
                'opened_vulns': 10,
                're_opened_vulns': 2,
                'risk_accepted_vulns': 3,
                'closed_vulns': 7,
                'confirmed_vulns': 17,
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
                'web_vulns': 9,
                'std_vulns': 6,
                'critical_vulns': 8,
                'high_vulns': 2,
                'info_vulns': 2,
                'low_vulns': 2,
                'medium_vulns': 1,
                'unclassified_vulns': 0,
                'opened_vulns': 15,
                're_opened_vulns': 4,
                'risk_accepted_vulns': 3,
                'closed_vulns': 8,
                'notclosed_vulns': 15,
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
                'web_vulns': 13,
                'std_vulns': 10,
                'critical_vulns': 12,
                'high_vulns': 2,
                'info_vulns': 2,
                'low_vulns': 2,
                'medium_vulns': 2,
                'unclassified_vulns': 3,
                'opened_vulns': 15,
                're_opened_vulns': 4,
                'risk_accepted_vulns': 3,
                'closed_vulns': 8,
                'total_vulns': 23,
            }
        },
    ])
    def test_workspace_stats(self,
                             vulnerability_factory,
                             vulnerability_web_factory,
                             host_factory,
                             test_client,
                             session,
                             query):
        from faraday.server.debouncer import Debouncer
        vulns = []
        host = host_factory.create(workspace=self.first_object)
        session.add(host)
        session.commit()
        for vulnerability in vulnerabilities:
            if vulnerability['type'] == 'web':
                vulns += vulnerability_web_factory.create_batch(vulnerability['count'],
                                                                workspace=self.first_object,
                                                                host=host,
                                                                service=None,
                                                                confirmed=vulnerability['confirmed'],
                                                                status=vulnerability['status'],
                                                                severity=vulnerability['severity'])
            else:
                vulns += vulnerability_factory.create_batch(vulnerability['count'],
                                                            workspace=self.first_object,
                                                            host=host,
                                                            service=None,
                                                            confirmed=vulnerability['confirmed'],
                                                            status=vulnerability['status'],
                                                            severity=vulnerability['severity'])
        session.add_all(vulns)
        session.commit()

        debouncer = Debouncer(wait=1)

        update_host_stats([host.id], [], workspace_id=self.first_object.id, debouncer=debouncer)
        time.sleep(3)

        res = test_client.get(self.url(self.first_object))
        assert res.status_code == 200

        # Determine the correct key prefixes based on the confirmed and only_opened params
        confirmed_suffix = '_confirmed' if query['params']['confirmed'] == 'true' else ''
        notclosed_suffix = '_notclosed' if query['params']['only_opened'] == 'true' else ''
        suffix = f'{notclosed_suffix}{confirmed_suffix}'

        stats = res.json['stats']
        result = query['result']

        # vulnerability types
        assert stats[f'code_vulns{suffix}'] == result['code_vulns']
        assert stats[f'web_vulns{suffix}'] == result['web_vulns']
        assert stats[f'std_vulns{suffix}'] == result['std_vulns']

        # vulnerability by severity
        assert stats[f'critical_vulns{suffix}'] == result['critical_vulns']
        assert stats[f'high_vulns{suffix}'] == result['high_vulns']
        assert stats[f'medium_vulns{suffix}'] == result['medium_vulns']
        assert stats[f'low_vulns{suffix}'] == result['low_vulns']
        assert stats[f'info_vulns{suffix}'] == result['info_vulns']
        assert stats[f'unclassified_vulns{suffix}'] == result['unclassified_vulns']

        # vulnerability by status
        assert stats[f'opened_vulns{confirmed_suffix}'] == result['opened_vulns']
        assert stats[f're_opened_vulns{confirmed_suffix}'] == result['re_opened_vulns']
        assert stats[f'risk_accepted_vulns{confirmed_suffix}'] == result['risk_accepted_vulns']
        assert stats[f'closed_vulns{confirmed_suffix}'] == result['closed_vulns']

        # total vulnerabilities by filters
        if suffix != '':
            assert stats[f'{suffix[1:]}_vulns'] == result[f'{suffix[1:]}_vulns']
        else:
            assert stats['total_vulns'] == result['total_vulns']

    @pytest.mark.skip_sql_dialect('sqlite')
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
        firs_ws = [ws['histogram'] for ws in res.json['rows'] if ws['name'] == self.first_object.name]
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

        second_ws = [ws['histogram'] for ws in res.json['rows'] if ws['name'] == second_workspace.name]
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
        firs_ws = [ws['histogram'] for ws in res.json['rows'] if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 20

        res = test_client.get('/v3/ws?histogram=true&histogram_days=[asdf, "adsf"]')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json['rows'] if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 20

        res = test_client.get('/v3/ws?histogram=true&histogram_days=[asdf, "adsf"]')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json['rows'] if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 20

        res = test_client.get('/v3/ws?histogram=true&histogram_days=5')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json['rows'] if ws['name'] == self.first_object.name]
        assert len(firs_ws[0]) == 5

        res = test_client.get('/v3/ws?histogram=true&histogram_days=365')
        assert res.status_code == 200
        firs_ws = [ws['histogram'] for ws in res.json['rows'] if ws['name'] == self.first_object.name]
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
                          vulnerability_web_factory,
                          host_factory):
        from faraday.server.debouncer import Debouncer
        host = host_factory.create(workspace=workspace)
        session.add(host)
        session.commit()
        vulns = vulnerability_factory.create_batch(10, workspace=workspace, host=host, service=None)
        session.add_all(vulns)
        session.commit()
        vulns = vulnerability_web_factory.create_batch(5, workspace=workspace, host=host, service=None)
        session.add_all(vulns)
        session.commit()

        debouncer = Debouncer(wait=1)

        update_host_stats([host.id], [], workspace_id=workspace.id, debouncer=debouncer)
        time.sleep(3)
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

    def test_bulk_update_workspaces(self, session, test_client, user, workspace_factory):
        # Clear existing data
        Workspace.query.delete()

        # Create workspaces using the factory
        ws1 = workspace_factory.create(name='test1', public=False, active=False)
        ws2 = workspace_factory.create(name='test2', public=False, active=False)
        ws3 = workspace_factory.create(name='test3', public=False, active=False)
        ws4 = workspace_factory.create(name='other_workspace', public=False, active=False)

        # Commit to ensure objects are in the database
        session.commit()

        # Define the bulk update request body
        bulk_update_body = {
            "ids": ["test1", "test2", "test3"],
            "active": True,
            "public": True,  # Additional fields can be updated
            "description": "TEST"
        }

        # Perform the bulk update request
        response = test_client.patch(
            '/v3/ws/bulk_update',
            json=bulk_update_body,
        )

        # Validate the response
        assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
        response_data = response.json
        assert response_data['updated'] == 3, "Expected 3 workspaces to be updated"

        # Re-fetch updated workspaces from the database
        updated_workspaces = Workspace.query.filter(Workspace.name.in_(bulk_update_body['ids'])).all()

        for ws in updated_workspaces:
            assert ws.active is True, f"Workspace {ws.name} should be active"
            assert ws.public is True, f"Workspace {ws.name} should be public"
            assert ws.description == 'TEST', "Workspace description should be TEST"

        # Validate unaffected workspace
        other_workspace = Workspace.query.filter_by(name='other_workspace').first()
        assert other_workspace.active is False, "Other workspaces should not be updated"
        assert other_workspace.public is False, "Other workspaces should not be updated"

    def test_patch_without_scope_preserves_existing_scope(self, session, test_client, workspace):
        # Add initial scope to workspace
        session.add(Scope(name='test.com', workspace=workspace))
        session.add(Scope(name='www.google.com', workspace=workspace))
        session.commit()

        # Verify initial scope is set
        initial_scope = {s.name for s in workspace.scope}
        assert initial_scope == {'test.com', 'www.google.com'}

        # PATCH without scope field - should preserve existing scope
        raw_data = {'description': 'updated description'}
        res = test_client.patch(self.url(obj=workspace), data=raw_data)
        assert res.status_code == 200

        # Verify scope is preserved
        session.refresh(workspace)
        final_scope = {s.name for s in workspace.scope}
        assert final_scope == initial_scope

    def test_patch_with_scope_updates_scope(self, session, test_client, workspace):
        # Add initial scope to workspace
        session.add(Scope(name='test.com', workspace=workspace))
        session.add(Scope(name='www.google.com', workspace=workspace))
        session.commit()

        # PATCH with scope field - should update scope
        new_scope = ['new.example.com', '192.168.1.1']
        raw_data = {'description': 'updated description', 'scope': new_scope}
        res = test_client.patch(self.url(obj=workspace), data=raw_data)
        assert res.status_code == 200
        assert set(res.json['scope']) == set(new_scope)

        # Verify scope is updated
        session.refresh(workspace)
        final_scope = {s.name for s in workspace.scope}
        assert final_scope == set(new_scope)
