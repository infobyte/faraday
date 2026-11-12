from copy import deepcopy
from datetime import datetime, timedelta

import pytest

from faraday.server.models import VulnerabilityGeneric, db
from faraday.server.utils.reports_processor import send_report_data
from faraday.server.utils.triage import SOURCE_IMPORT, TriageState, apply_triage_rules
from tests.factories import UserFactory
from tests.test_api_bulk_create import command_data, host_data, new_empty_command, vuln_data

pytestmark = pytest.mark.usefixtures('logged_user')


def import_report(workspace, user, status='open', **vuln_fields):
    vuln = deepcopy(vuln_data)
    vuln.update(status=status, **vuln_fields)
    host = deepcopy(host_data)
    host['vulnerabilities'] = [vuln]
    command = new_empty_command(workspace)
    send_report_data(workspace.name, command.id, {'hosts': [host], 'command': dict(command_data)}, user.id, True)
    db.session.expire_all()
    return VulnerabilityGeneric.query.filter_by(workspace_id=workspace.id, name=vuln_data['name']).one()


def set_state(vuln, **values):
    for name, value in values.items():
        setattr(vuln, name, value)
    db.session.commit()


class TestNewImportedVulns:

    def test_open_vuln_is_pending(self, session, workspace, logged_user):
        vuln = import_report(workspace, logged_user)

        assert (vuln.confirmed, vuln.false_positive, vuln.triaged, vuln.triaged_by_id, vuln.triaged_at) == \
            (False, False, False, None, None)

    def test_closed_vuln_is_triaged_by_the_importer(self, session, workspace, logged_user):
        vuln = import_report(workspace, logged_user, status='closed')

        assert (vuln.triaged, vuln.triaged_by_id) == (True, logged_user.id)
        assert vuln.triaged_at is not None

    def test_confirmed_by_the_plugin_is_triaged_by_the_importer(self, session, workspace, logged_user):
        vuln = import_report(workspace, logged_user, confirmed=True)

        assert (vuln.confirmed, vuln.triaged, vuln.triaged_by_id) == (True, True, logged_user.id)

    def test_import_cant_mark_false_positives(self, session, workspace, logged_user):
        vuln = import_report(workspace, logged_user, false_positive=True)

        assert (vuln.false_positive, vuln.status) == (False, 'open')

class TestReimport:

    def test_closing_triages_with_the_importer(self, session, workspace, logged_user):
        vuln = import_report(workspace, logged_user)

        vuln = import_report(workspace, logged_user, status='closed')

        assert (vuln.status, vuln.triaged, vuln.triaged_by_id) == ('closed', True, logged_user.id)
        assert vuln.triaged_at is not None

    def test_reopening_keeps_triaged(self, session, workspace, logged_user):
        triager = UserFactory.create()
        triaged_at = datetime(2026, 10, 1)
        vuln = import_report(workspace, logged_user)
        set_state(vuln, status='closed', triaged=True, triaged_by=triager, triaged_at=triaged_at)

        vuln = import_report(workspace, logged_user, status='open')

        assert (vuln.status, vuln.triaged, vuln.triaged_by_id, vuln.triaged_at) == \
            ('re-opened', True, triager.id, triaged_at)

    def test_reopening_a_pending_vuln_keeps_it_pending(self, session, workspace, logged_user):
        vuln = import_report(workspace, logged_user)
        set_state(vuln, status='closed')

        vuln = import_report(workspace, logged_user, status='open')

        assert (vuln.status, vuln.triaged) == ('re-opened', False)

    def test_false_positive_stays_closed(self, session, workspace, logged_user):
        vuln = import_report(workspace, logged_user)
        last_detected = datetime.utcnow() - timedelta(days=30)
        set_state(vuln, status='closed', false_positive=True, triaged=True, last_detected=last_detected)

        vuln = import_report(workspace, logged_user, status='open')

        assert (vuln.status, vuln.false_positive, vuln.triaged) == ('closed', True, True)
        assert vuln.last_detected > last_detected

STATES = {
    'pending open': TriageState(confirmed=False, false_positive=False, triaged=False, status='open'),
    'pending re-opened': TriageState(confirmed=False, false_positive=False, triaged=False, status='re-opened'),
    'pending closed': TriageState(confirmed=False, false_positive=False, triaged=False, status='closed'),
    'triaged closed': TriageState(confirmed=False, false_positive=False, triaged=True, status='closed'),
    'confirmed open': TriageState(confirmed=True, false_positive=False, triaged=True, status='open'),
    'risk accepted': TriageState(confirmed=False, false_positive=False, triaged=True, status='risk-accepted'),
    'false positive': TriageState(confirmed=False, false_positive=True, triaged=True, status='closed'),
}


def requested_status(current_status, incoming_status):
    """The status change an import asks for: it reopens closed vulns it detects and
    closes open ones the plugin reports closed (see insert_vulnerabilities)."""
    if incoming_status in ('open', 're-opened') and current_status == 'closed':
        return 're-opened'
    if incoming_status == 'closed' and current_status in ('open', 're-opened'):
        return 'closed'
    return None


@pytest.mark.parametrize('incoming_status', ['open', 'closed'])
@pytest.mark.parametrize('state_name', STATES.keys())
def test_reimport_matches_shared_triage_rules(session, workspace, logged_user, state_name, incoming_status):
    current = STATES[state_name]
    vuln = import_report(workspace, logged_user)
    set_state(vuln, confirmed=current.confirmed, false_positive=current.false_positive,
              triaged=current.triaged, status=current.status, triaged_by=None, triaged_at=None)

    vuln = import_report(workspace, logged_user, status=incoming_status)

    expected = apply_triage_rules(current, {'status': requested_status(current.status, incoming_status)},
                                  user_id=logged_user.id, source=SOURCE_IMPORT)
    assert TriageState.from_vuln(vuln) == expected.state
    assert vuln.triaged_by_id == expected.values.get('triaged_by_id')
    assert (vuln.triaged_at is not None) == ('triaged_at' in expected.values)
