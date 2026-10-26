import json
from datetime import datetime

import pytest

from faraday.server.models import VulnerabilityGeneric, VulnerabilityStatusHistory
from tests.factories import HostFactory, UserFactory, VulnerabilityFactory

pytestmark = pytest.mark.usefixtures('logged_user')


def vuln_url(workspace, vuln=None):
    url = f'/v3/ws/{workspace.name}/vulns'
    return f'{url}/{vuln.id}' if vuln else url


def history_of(session, vuln):
    return [
        (row.field, row.status, row.value)
        for row in session.query(VulnerabilityStatusHistory)
        .filter_by(vulnerability_id=vuln.id)
        .order_by(VulnerabilityStatusHistory.id)
    ]


def reload(session, vuln):
    session.expire_all()
    return VulnerabilityGeneric.query.get(vuln.id)


class TestSingleVulnTriage:

    def test_mark_false_positive(self, test_client, session, workspace, logged_user):
        vuln = VulnerabilityFactory.create(workspace=workspace, status='open', confirmed=True, triaged=True)
        session.commit()

        res = test_client.patch(vuln_url(workspace, vuln), json={'false_positive': True})

        assert res.status_code == 200
        assert (res.json['confirmed'], res.json['false_positive'], res.json['triaged'], res.json['status']) == \
            (False, True, True, 'closed')
        assert res.json['triaged_by'] == logged_user.username
        assert res.json['triaged_at'] is not None

    def test_confirm_false_positive_reopens_it(self, test_client, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace, status='closed', false_positive=True, triaged=True)
        session.commit()

        res = test_client.patch(vuln_url(workspace, vuln), json={'confirmed': True})

        assert res.status_code == 200
        assert (res.json['confirmed'], res.json['false_positive'], res.json['triaged'], res.json['status']) == \
            (True, False, True, 're-opened')

    def test_reopen_false_positive_sends_it_back_to_the_backlog(self, test_client, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace, status='closed', false_positive=True, triaged=True)
        session.commit()

        res = test_client.patch(vuln_url(workspace, vuln), json={'status': 're-opened'})

        assert res.status_code == 200
        assert (res.json['false_positive'], res.json['triaged'], res.json['status']) == (False, False, 're-opened')

    def test_unconfirm_keeps_last_triage_record(self, test_client, session, workspace):
        triager = UserFactory.create()
        vuln = VulnerabilityFactory.create(workspace=workspace, status='closed', confirmed=True, triaged=True,
                                           triaged_by=triager)
        session.commit()

        res = test_client.patch(vuln_url(workspace, vuln), json={'confirmed': False})

        assert res.status_code == 200
        assert (res.json['confirmed'], res.json['triaged'], res.json['status']) == (False, False, 'closed')
        assert res.json['triaged_by'] == triager.username

    def test_close_by_hand_triages(self, test_client, session, workspace, logged_user):
        vuln = VulnerabilityFactory.create(workspace=workspace, status='open')
        session.commit()

        res = test_client.patch(vuln_url(workspace, vuln), json={'status': 'closed'})

        assert res.status_code == 200
        assert (res.json['confirmed'], res.json['triaged'], res.json['triaged_by']) == \
            (False, True, logged_user.username)

    def test_put_resending_the_vuln_changes_nothing(self, test_client, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace, status='closed', false_positive=True, triaged=True)
        session.commit()
        data = test_client.get(vuln_url(workspace, vuln)).json
        # The dumped issuetracker can't be loaded back on this edition, unrelated to triage
        data.pop('issuetracker', None)

        res = test_client.put(vuln_url(workspace, vuln), json=data)

        assert res.status_code == 200
        assert (res.json['false_positive'], res.json['status']) == (True, 'closed')

    @pytest.mark.parametrize('changes, expected', [
        ({'status': 're-opened'}, (False, False, False, 're-opened')),
        ({'confirmed': True}, (True, False, True, 're-opened')),
        ({'status': 'risk-accepted'}, (True, False, True, 'risk-accepted')),
    ])
    def test_put_full_body_on_false_positive(self, test_client, session, workspace, changes, expected):
        # The body still carries false_positive=true, the vuln's current value
        vuln = VulnerabilityFactory.create(workspace=workspace, status='closed', false_positive=True, triaged=True)
        session.commit()
        data = test_client.get(vuln_url(workspace, vuln)).json
        # The dumped issuetracker can't be loaded back on this edition, unrelated to triage
        data.pop('issuetracker', None)
        data.update(changes)

        res = test_client.put(vuln_url(workspace, vuln), json=data)

        assert res.status_code == 200, res.json
        assert (res.json['confirmed'], res.json['false_positive'], res.json['triaged'], res.json['status']) == expected

    @pytest.mark.parametrize('data', [
        {'confirmed': True, 'false_positive': True},
        {'false_positive': True, 'status': 're-opened'},
    ])
    def test_contradictory_changes_are_rejected(self, test_client, session, workspace, data):
        vuln = VulnerabilityFactory.create(workspace=workspace, status='open')
        session.commit()

        res = test_client.patch(vuln_url(workspace, vuln), json=data)

        assert res.status_code == 400
        assert (reload(session, vuln).false_positive, reload(session, vuln).confirmed) == (False, False)

    @pytest.mark.parametrize('field, value', [
        ('triaged', True),
        ('triaged_by', 'someone'),
        ('triaged_at', '2026-01-01T00:00:00'),
    ])
    def test_triage_fields_are_read_only(self, test_client, session, workspace, field, value):
        vuln = VulnerabilityFactory.create(workspace=workspace, status='open')
        session.commit()

        test_client.patch(vuln_url(workspace, vuln), json={field: value})

        vuln = reload(session, vuln)
        assert (vuln.triaged, vuln.triaged_by_id, vuln.triaged_at) == (False, None, None)


def test_no_history_is_recorded(test_client, session, workspace):
    vuln = VulnerabilityFactory.create(workspace=workspace, status='open', confirmed=True, triaged=True)
    session.commit()

    res = test_client.patch(vuln_url(workspace, vuln), json={'false_positive': True})

    assert res.status_code == 200
    assert history_of(session, vuln) == []


class TestCreateVulnTriage:

    def _vuln_data(self, workspace, **kwargs):
        host = HostFactory.create(workspace=workspace)
        data = VulnerabilityFactory.build_dict(workspace=workspace, host=host, status='open')
        data.pop('confirmed', None)
        data.update(kwargs)
        return data

    def test_created_by_hand_comes_confirmed(self, test_client, session, workspace, logged_user):
        data = self._vuln_data(workspace)
        session.commit()

        res = test_client.post(vuln_url(workspace), json=data)

        assert res.status_code == 201
        vuln = VulnerabilityGeneric.query.get(res.json['_id'])
        assert (vuln.confirmed, vuln.triaged, vuln.triaged_by_id) == (True, True, logged_user.id)
        assert vuln.triaged_at == vuln.create_date

    def test_explicitly_unconfirmed(self, test_client, session, workspace):
        data = self._vuln_data(workspace, confirmed=False)
        session.commit()

        res = test_client.post(vuln_url(workspace), json=data)

        assert res.status_code == 201
        assert (res.json['confirmed'], res.json['triaged'], res.json['triaged_by']) == (False, False, None)

    def test_created_as_false_positive(self, test_client, session, workspace):
        data = self._vuln_data(workspace, false_positive=True)
        session.commit()

        res = test_client.post(vuln_url(workspace), json=data)

        assert res.status_code == 201
        assert (res.json['confirmed'], res.json['false_positive'], res.json['triaged'], res.json['status']) == \
            (False, True, True, 'closed')
        vuln = VulnerabilityGeneric.query.get(res.json['_id'])


class TestBulkTriage:

    @pytest.fixture
    def vulns(self, session, workspace):
        vulns = {
            'pending': VulnerabilityFactory.create(workspace=workspace, status='open'),
            'confirmed': VulnerabilityFactory.create(workspace=workspace, status='open', confirmed=True,
                                                     triaged=True),
            'false_positive': VulnerabilityFactory.create(workspace=workspace, status='closed',
                                                          false_positive=True, triaged=True),
        }
        session.commit()
        return vulns

    def test_mark_false_positive_on_mixed_selection(self, test_client, session, workspace, vulns, logged_user):
        ids = [vuln.id for vuln in vulns.values()]

        res = test_client.patch(vuln_url(workspace), json={'ids': ids, 'false_positive': True})

        assert res.status_code == 200
        assert res.json['updated'] == 3
        for name in ('pending', 'confirmed'):
            vuln = reload(session, vulns[name])
            assert (vuln.confirmed, vuln.false_positive, vuln.triaged, vuln.status) == (False, True, True, 'closed')
            assert vuln.triaged_by_id == logged_user.id
        # Already a false positive: nothing changes, nothing recorded

    def test_remove_false_positive(self, test_client, session, workspace, vulns):
        ids = [vuln.id for vuln in vulns.values()]

        res = test_client.patch(vuln_url(workspace), json={'ids': ids, 'false_positive': False})

        assert res.status_code == 200
        vuln = reload(session, vulns['false_positive'])
        assert (vuln.false_positive, vuln.triaged, vuln.status) == (False, False, 're-opened')
        assert reload(session, vulns['confirmed']).confirmed is True

    def test_triage_and_other_fields_together(self, test_client, session, workspace, vulns):
        res = test_client.patch(vuln_url(workspace), json={'ids': [vulns['pending'].id], 'confirmed': True,
                                                           'severity': 'critical'})

        assert res.status_code == 200
        vuln = reload(session, vulns['pending'])
        assert (vuln.confirmed, vuln.triaged, vuln.severity) == (True, True, 'critical')

    def test_contradictory_changes_are_rejected(self, test_client, session, workspace, vulns):
        res = test_client.patch(vuln_url(workspace), json={'ids': [vulns['pending'].id], 'confirmed': True,
                                                           'false_positive': True})

        assert res.status_code == 400
        assert reload(session, vulns['pending']).confirmed is False


class TestTriageFilters:

    @pytest.fixture
    def vulns(self, session, workspace):
        triager = UserFactory.create(username='triager')
        other = UserFactory.create(username='other_triager')
        vulns = {
            'pending': VulnerabilityFactory.create(workspace=workspace, name='pending', status='open'),
            'confirmed': VulnerabilityFactory.create(workspace=workspace, name='confirmed', status='open',
                                                     confirmed=True, triaged=True, triaged_by=triager,
                                                     triaged_at=datetime(2026, 10, 1), creator=other),
            'false_positive': VulnerabilityFactory.create(workspace=workspace, name='false_positive',
                                                          status='closed', false_positive=True, triaged=True,
                                                          triaged_by=other, triaged_at=datetime(2026, 10, 2)),
        }
        session.commit()
        return vulns

    def _filter(self, test_client, workspace, query):
        res = test_client.get(f'{vuln_url(workspace)}/filter?q={json.dumps(query)}')
        assert res.status_code == 200, res.json
        return res.json

    def _names(self, filter_response):
        return sorted(vuln['value']['name'] for vuln in filter_response['vulnerabilities'])

    @pytest.mark.parametrize('param, expected', [
        ('false_positive=true', ['false_positive']),
        ('false_positive=false', ['confirmed', 'pending']),
        ('triaged=true', ['confirmed', 'false_positive']),
        ('triaged=false', ['pending']),
        ('triaged_by=triager', ['confirmed']),
    ])
    def test_legacy_filters(self, test_client, workspace, vulns, param, expected):
        res = test_client.get(f'{vuln_url(workspace)}?{param}')

        assert res.status_code == 200
        assert sorted(vuln['value']['name'] for vuln in res.json['vulnerabilities']) == expected

    @pytest.mark.parametrize('filters, expected', [
        ([{'name': 'false_positive', 'op': '==', 'val': True}], ['false_positive']),
        ([{'name': 'triaged', 'op': '==', 'val': False}], ['pending']),
        ([{'name': 'triaged_by', 'op': '==', 'val': 'triager'}], ['confirmed']),
        ([{'name': 'triaged_by__username', 'op': '==', 'val': 'other_triager'}], ['false_positive']),
        ([{'name': 'triaged_at', 'op': 'is_null', 'val': ''}], ['pending']),
        # Combined with a creator filter, which joins User through creator_id
        ([{'name': 'triaged_by', 'op': '==', 'val': 'triager'},
          {'name': 'creator', 'op': '==', 'val': 'other_triager'}], ['confirmed']),
    ])
    def test_json_filters(self, test_client, workspace, vulns, filters, expected):
        assert self._names(self._filter(test_client, workspace, {'filters': filters})) == expected

    def test_json_order_by_triaged_by_username(self, test_client, workspace, vulns):
        res = self._filter(test_client, workspace,
                           {'order_by': [{'field': 'triaged_by__username', 'direction': 'desc'}]})

        names = [vuln['value']['name'] for vuln in res['vulnerabilities']]
        # desc puts NULLs last
        assert names == ['confirmed', 'false_positive', 'pending']

    @pytest.mark.parametrize('field', ['triaged', 'false_positive', 'triaged_at'])
    def test_json_order_by_columns(self, test_client, workspace, vulns, field):
        res = self._filter(test_client, workspace, {'order_by': [{'field': field, 'direction': 'asc'}]})

        assert len(res['vulnerabilities']) == 3

    def test_json_group_by_triaged_by_username(self, test_client, workspace, vulns):
        res = self._filter(test_client, workspace, {'group_by': [{'field': 'triaged_by__username'}]})

        groups = {group['value']['triaged_by__username']: group['value']['count'] for group in res['vulnerabilities']}
        assert groups == {'triager': 1, 'other_triager': 1, None: 1}

    def test_json_group_by_triaged(self, test_client, workspace, vulns):
        res = self._filter(test_client, workspace, {'group_by': [{'field': 'triaged'}]})

        groups = {group['value']['triaged']: group['value']['count'] for group in res['vulnerabilities']}
        assert groups == {True: 2, False: 1}

    @pytest.mark.parametrize('field', ['triaged', 'false_positive', 'triaged_at', 'triaged_by'])
    def test_legacy_sort(self, test_client, workspace, vulns, field):
        res = test_client.get(f'{vuln_url(workspace)}?sort={field}&sort_dir=desc')

        assert res.status_code == 200
        assert len(res.json['vulnerabilities']) == 3

    def test_legacy_sort_by_triaged(self, test_client, workspace, vulns):
        res = test_client.get(f'{vuln_url(workspace)}?sort=triaged&sort_dir=asc')

        assert res.json['vulnerabilities'][0]['value']['name'] == 'pending'

    @pytest.mark.parametrize('group_by, expected', [
        ('triaged', {'True': 2, 'False': 1}),
        ('false_positive', {'True': 1, 'False': 2}),
    ])
    def test_count_group_by(self, test_client, workspace, vulns, group_by, expected):
        res = test_client.get(f'{vuln_url(workspace)}/count?group_by={group_by}')

        assert res.status_code == 200
        assert {group['name']: group['count'] for group in res.json['groups']} == expected

    def test_filter_on_triaged_by_password_is_rejected(self, test_client, workspace, vulns):
        query = {'filters': [{'name': 'triaged_by__password', 'op': '==', 'val': 'x'}]}

        res = test_client.get(f'{vuln_url(workspace)}/filter?q={json.dumps(query)}')

        assert res.status_code == 400


class TestConfirmedQueryParam:

    @pytest.fixture
    def vulns(self, session, workspace):
        VulnerabilityFactory.create(workspace=workspace, name='confirmed', confirmed=True)
        VulnerabilityFactory.create(workspace=workspace, name='unconfirmed', confirmed=False)
        session.commit()

    @pytest.mark.parametrize('param, expected', [
        ('', {'confirmed', 'unconfirmed'}),
        ('?confirmed=', {'confirmed', 'unconfirmed'}),
        ('?confirmed=true', {'confirmed'}),
        ('?confirmed=1', {'confirmed'}),
        ('?confirmed=false', {'unconfirmed'}),
        ('?confirmed=0', {'unconfirmed'}),
    ])
    def test_export_csv(self, test_client, workspace, vulns, param, expected):
        res = test_client.get(f'{vuln_url(workspace)}/export_csv{param}')

        assert res.status_code == 200
        rows = res.data.decode('utf-8').splitlines()[1:]
        names = {row.split(',')[3] for row in rows}
        assert names == expected

    def test_invalid_value_is_rejected(self, test_client, workspace, vulns):
        res = test_client.get(f'{vuln_url(workspace)}/export_csv?confirmed=maybe')

        assert res.status_code == 400
