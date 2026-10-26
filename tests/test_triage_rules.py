import json
from contextlib import contextmanager
from datetime import datetime

import pytest
from sqlalchemy import event, update

from faraday.server.models import VulnerabilityGeneric, db
from faraday.server.utils.triage import (
    SOURCE_IMPORT,
    TriageState,
    TriageValidationError,
    apply_triage_rules,
    build_history_rows,
    bulk_apply_triage,
    group_events,
    lock_triage_state,
    ungroup_events,
)

NOW = datetime(2026, 10, 23, 12, 0, 0)
USER_ID = 7

PENDING = TriageState(confirmed=False, false_positive=False, triaged=False, status='open')
BY_STATUS = TriageState(confirmed=False, false_positive=False, triaged=True, status='closed')
CONFIRMED = TriageState(confirmed=True, false_positive=False, triaged=True, status='open')
FALSE_POSITIVE = TriageState(confirmed=False, false_positive=True, triaged=True, status='closed')


def state(confirmed, false_positive, triaged, status):
    return TriageState(confirmed=confirmed, false_positive=false_positive, triaged=triaged, status=status)


def apply(current, source='manual', **changes):
    return apply_triage_rules(current, changes, user_id=USER_ID, now=NOW, source=source)


# (current, changes, expected state, triaged by the action, expected events)
CASES = {
    'confirm pending': (
        PENDING, {'confirmed': True}, state(True, False, True, 'open'), True,
        [('confirmed', True)]),
    'confirm triaged by status': (
        BY_STATUS, {'confirmed': True}, state(True, False, True, 'closed'), True,
        [('confirmed', True)]),
    'mark pending as false positive': (
        PENDING, {'false_positive': True}, state(False, True, True, 'closed'), True,
        [('false_positive', True), ('status', 'closed')]),
    'mark confirmed as false positive': (
        CONFIRMED, {'false_positive': True}, state(False, True, True, 'closed'), True,
        [('confirmed', False), ('false_positive', True), ('status', 'closed')]),
    'mark false positive with status closed': (
        PENDING, {'false_positive': True, 'status': 'closed'}, state(False, True, True, 'closed'), True,
        [('false_positive', True), ('status', 'closed')]),
    'confirm false positive': (
        FALSE_POSITIVE, {'confirmed': True}, state(True, False, True, 're-opened'), True,
        [('confirmed', True), ('false_positive', False), ('status', 're-opened')]),
    'remove false positive': (
        FALSE_POSITIVE, {'false_positive': False}, state(False, False, False, 're-opened'), False,
        [('false_positive', False), ('status', 're-opened')]),
    'reopen false positive by hand': (
        FALSE_POSITIVE, {'status': 're-opened'}, state(False, False, False, 're-opened'), False,
        [('false_positive', False), ('status', 're-opened')]),
    'risk accept false positive': (
        FALSE_POSITIVE, {'status': 'risk-accepted'}, state(True, False, True, 'risk-accepted'), True,
        [('confirmed', True), ('false_positive', False), ('status', 'risk-accepted')]),
    'close pending by hand': (
        PENDING, {'status': 'closed'}, state(False, False, True, 'closed'), True,
        [('status', 'closed')]),
    'reopen closed pending by hand': (
        state(False, False, False, 'closed'), {'status': 're-opened'}, state(False, False, True, 're-opened'), True,
        [('status', 're-opened')]),
    'risk accept pending': (
        PENDING, {'status': 'risk-accepted'}, state(False, False, True, 'risk-accepted'), True,
        [('status', 'risk-accepted')]),
    'close confirmed by hand': (
        CONFIRMED, {'status': 'closed'}, state(True, False, True, 'closed'), True,
        [('status', 'closed')]),
    'unconfirm': (
        CONFIRMED, {'confirmed': False}, state(False, False, False, 'open'), False,
        [('confirmed', False)]),
    'unconfirm after a status triage': (
        state(True, False, True, 'closed'), {'confirmed': False}, state(False, False, False, 'closed'), False,
        [('confirmed', False)]),
    'unconfirm wins over a status change': (
        CONFIRMED, {'confirmed': False, 'status': 'closed'}, state(False, False, False, 'closed'), False,
        [('confirmed', False), ('status', 'closed')]),
    'close false positive by hand is a no-op': (
        FALSE_POSITIVE, {'status': 'closed'}, FALSE_POSITIVE, False, []),
    'unconfirm a false positive is a no-op': (
        FALSE_POSITIVE, {'confirmed': False}, FALSE_POSITIVE, False, []),
    'remove false positive mark from a non false positive is a no-op': (
        CONFIRMED, {'false_positive': False}, CONFIRMED, False, []),
    'resending the same values is a no-op': (
        CONFIRMED, {'confirmed': True, 'false_positive': False, 'status': 'open'}, CONFIRMED, False, []),
    # A full-body PUT repeats the current values of the fields it doesn't change
    'full body: confirm a false positive': (
        FALSE_POSITIVE, {'confirmed': True, 'false_positive': True, 'status': 'closed'},
        state(True, False, True, 're-opened'), True,
        [('confirmed', True), ('false_positive', False), ('status', 're-opened')]),
    'full body: reopen a false positive': (
        FALSE_POSITIVE, {'confirmed': False, 'false_positive': True, 'status': 're-opened'},
        state(False, False, False, 're-opened'), False,
        [('false_positive', False), ('status', 're-opened')]),
    'full body: risk accept a false positive': (
        FALSE_POSITIVE, {'confirmed': False, 'false_positive': True, 'status': 'risk-accepted'},
        state(True, False, True, 'risk-accepted'), True,
        [('confirmed', True), ('false_positive', False), ('status', 'risk-accepted')]),
    'full body: mark an open vuln as false positive': (
        PENDING, {'confirmed': False, 'false_positive': True, 'status': 'open'},
        state(False, True, True, 'closed'), True,
        [('false_positive', True), ('status', 'closed')]),
}


@pytest.mark.parametrize('current, changes, expected, stamped, events', CASES.values(), ids=CASES.keys())
def test_triage_rules(current, changes, expected, stamped, events):
    result = apply(current, **changes)

    assert result.state == expected
    assert result.events == events
    if stamped:
        assert result.values['triaged_by_id'] == USER_ID
        assert result.values['triaged_at'] == NOW
    else:
        # triaged_by/triaged_at are kept as the record of the last triage
        assert 'triaged_by_id' not in result.values
        assert 'triaged_at' not in result.values
    assert result.changed == (expected != current or stamped)


def test_values_only_hold_changed_columns():
    result = apply(BY_STATUS, confirmed=True)

    assert result.values == {'confirmed': True, 'triaged_by_id': USER_ID, 'triaged_at': NOW}


def test_triaged_and_unknown_keys_are_ignored():
    result = apply(PENDING, triaged=True, name='foo')

    assert not result.changed


@pytest.mark.parametrize('changes', [
    {'confirmed': True, 'false_positive': True},
    {'false_positive': True, 'status': 're-opened'},
    {'false_positive': True, 'status': 'risk-accepted'},
])
def test_contradictory_changes_are_rejected(changes):
    with pytest.raises(TriageValidationError):
        apply(PENDING, **changes)


IMPORT_CASES = {
    'import closes pending': (
        PENDING, 'closed', state(False, False, True, 'closed'), True),
    'import reopens closed vuln without changing triaged': (
        state(False, False, False, 'closed'), 're-opened', state(False, False, False, 're-opened'), False),
    'import reopens triaged closed vuln without changing triaged': (
        BY_STATUS, 're-opened', state(False, False, True, 're-opened'), False),
    'import keeps false positive closed': (
        FALSE_POSITIVE, 're-opened', FALSE_POSITIVE, False),
}


@pytest.mark.parametrize('current, status, expected, stamped', IMPORT_CASES.values(), ids=IMPORT_CASES.keys())
def test_import_triage_rules(current, status, expected, stamped):
    result = apply(current, source=SOURCE_IMPORT, status=status)

    assert result.state == expected
    assert ('triaged_by_id' in result.values) == stamped


def test_import_ignores_confirmed_and_false_positive_changes():
    result = apply(PENDING, source=SOURCE_IMPORT, confirmed=True, false_positive=False)

    assert not result.changed


def test_group_events_round_trip():
    events_by_vuln = {1: [('status', 'closed')], 2: [('status', 'closed')],
                      3: [('confirmed', False), ('false_positive', True), ('status', 'closed')]}

    grouped = group_events(events_by_vuln)

    assert len(grouped) == 2
    assert json.loads(json.dumps(grouped)) == grouped  # Celery sends it as JSON
    assert ungroup_events(grouped) == events_by_vuln


def test_build_history_rows_share_user_and_date():
    rows = build_history_rows({1: [('confirmed', False), ('false_positive', True), ('status', 'closed')]},
                              user_id=USER_ID, change_date=NOW)

    assert [(row['field'], row['status'], row['value']) for row in rows] == [
        ('confirmed', None, False),
        ('false_positive', None, True),
        ('status', 'closed', None),
    ]
    assert {(row['vulnerability_id'], row['user_id'], row['change_date']) for row in rows} == {(1, USER_ID, NOW)}


class TestBulkApplyTriage:

    @pytest.fixture
    def vulns(self, session, vulnerability_factory, workspace):
        vulns = {
            'pending': vulnerability_factory.create(workspace=workspace, status='open'),
            'confirmed': vulnerability_factory.create(workspace=workspace, status='open', confirmed=True,
                                                      triaged=True),
            'false_positive': vulnerability_factory.create(workspace=workspace, status='closed',
                                                           false_positive=True, triaged=True),
        }
        session.commit()
        return vulns

    def test_mixed_selection_applies_each_vuln_rules(self, session, vulns, user):
        session.add(user)
        session.commit()
        ids = [vuln.id for vuln in vulns.values()]

        result = bulk_apply_triage(ids, {'confirmed': True}, user_id=user.id, now=NOW)
        session.commit()

        pending, confirmed, false_positive = (VulnerabilityGeneric.query.get(vulns[name].id)
                                              for name in ('pending', 'confirmed', 'false_positive'))
        assert (pending.confirmed, pending.triaged, pending.status) == (True, True, 'open')
        assert (false_positive.confirmed, false_positive.false_positive, false_positive.status) == \
            (True, False, 're-opened')
        assert pending.triaged_by_id == false_positive.triaged_by_id == user.id
        assert pending.triaged_at == false_positive.triaged_at == NOW
        # Already confirmed: nothing to do
        assert confirmed.triaged_by_id is None
        assert sorted(result.updated_ids) == sorted([pending.id, false_positive.id])
        assert result.status_changes == {false_positive.id: 're-opened'}
        assert result.previous_status == {false_positive.id: 'closed'}
        assert result.events_by_vuln[false_positive.id] == [
            ('confirmed', True), ('false_positive', False), ('status', 're-opened')]

    def test_extra_filters_narrow_the_vulns(self, session, vulns, second_workspace, vulnerability_factory):
        other = vulnerability_factory.create(workspace=second_workspace, status='open')
        session.commit()
        ids = [vulns['pending'].id, other.id]

        result = bulk_apply_triage(ids, {'false_positive': True}, now=NOW,
                                   extra_filters=[VulnerabilityGeneric.workspace_id == vulns['pending'].workspace_id])
        session.commit()

        assert result.updated_ids == [vulns['pending'].id]
        assert VulnerabilityGeneric.query.get(other.id).false_positive is False

    def test_contradictory_changes_are_rejected(self, vulns):
        with pytest.raises(TriageValidationError):
            bulk_apply_triage([vulns['pending'].id], {'confirmed': True, 'false_positive': True})

    def test_without_triage_changes_does_nothing(self, vulns):
        result = bulk_apply_triage([vulns['pending'].id], {'severity': 'high'})

        assert result.updated_ids == []


@contextmanager
def capture_sql():
    statements = []

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db.engine, 'before_cursor_execute', before_cursor_execute)
    try:
        yield statements
    finally:
        event.remove(db.engine, 'before_cursor_execute', before_cursor_execute)


class TestConcurrentTriage:
    """Two actions on the same vuln must not both decide from the same state."""

    def test_bulk_locks_the_rows_it_reads(self, session, vulnerability_factory):
        vuln = vulnerability_factory.create(status='open')
        session.commit()
        vuln_id = vuln.id

        with capture_sql() as statements:
            bulk_apply_triage([vuln_id], {'confirmed': True})

        select = next(statement for statement in statements if statement.lstrip().upper().startswith('SELECT'))
        assert 'FOR UPDATE' in select
        assert 'ORDER BY' in select

    def test_single_vuln_decides_from_the_saved_state(self, session, vulnerability_factory):
        vuln = vulnerability_factory.create(status='open')
        session.commit()
        assert vuln.confirmed is False
        # Another request confirms it after this one loaded the vuln
        session.execute(update(VulnerabilityGeneric).where(VulnerabilityGeneric.id == vuln.id)
                        .values(confirmed=True, triaged=True),
                        execution_options={'synchronize_session': False})
        assert vuln.confirmed is False  # stale

        with capture_sql() as statements:
            current = lock_triage_state(vuln)

        assert (current.confirmed, current.triaged) == (True, True)
        assert vuln.confirmed is True
        assert any('FOR UPDATE' in statement for statement in statements)
        # Marking it as false positive now also unconfirms it
        assert apply_triage_rules(current, {'false_positive': True}).values['confirmed'] is False

