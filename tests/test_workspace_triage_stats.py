from unittest import mock

import pytest

from faraday.server.debouncer import update_workspace_vulns_count
from faraday.server.models import Workspace, db
from faraday.server.utils.workflows import _perform_triage_action
from tests.factories import (
    HostFactory,
    ServiceFactory,
    SourceCodeFactory,
    VulnerabilityCodeFactory,
    VulnerabilityFactory,
    VulnerabilityWebFactory,
)


@pytest.fixture
def workspace_with_triage(session, workspace):
    host = HostFactory.create(workspace=workspace)
    other_host = HostFactory.create(workspace=workspace)
    service = ServiceFactory.create(workspace=workspace, host=other_host)
    false_positive = {'false_positive': True, 'triaged': True, 'status': 'closed'}
    VulnerabilityFactory.create(workspace=workspace, host=host, service=None, severity='high', **false_positive)
    VulnerabilityFactory.create(workspace=workspace, host=host, service=None, severity='high', **false_positive)
    VulnerabilityWebFactory.create(workspace=workspace, service=service, severity='critical', **false_positive)
    VulnerabilityCodeFactory.create(workspace=workspace, source_code=SourceCodeFactory.create(workspace=workspace),
                                    severity='informational', **false_positive)
    # Pending triage
    VulnerabilityFactory.create(workspace=workspace, host=host, service=None, severity='low', status='open')
    VulnerabilityFactory.create(workspace=workspace, host=host, service=None, severity='low', status='closed')
    # Confirmed
    VulnerabilityFactory.create(workspace=workspace, host=host, service=None, severity='medium', status='open',
                                confirmed=True, triaged=True)
    session.commit()
    return workspace


def test_debouncer_counts_false_positives_and_pending_triage(session, workspace_with_triage):
    update_workspace_vulns_count(workspace_id=workspace_with_triage.id)
    db.session.expire_all()

    ws = Workspace.query.get(workspace_with_triage.id)
    assert ws.vulnerability_false_positive_count == 4
    assert (ws.vulnerability_standard_false_positive_count, ws.vulnerability_web_false_positive_count,
            ws.vulnerability_code_false_positive_count) == (2, 1, 1)
    assert (ws.vulnerability_critical_false_positive_count, ws.vulnerability_high_false_positive_count,
            ws.vulnerability_medium_false_positive_count, ws.vulnerability_low_false_positive_count,
            ws.vulnerability_informational_false_positive_count,
            ws.vulnerability_unclassified_false_positive_count) == (1, 2, 0, 0, 1, 0)
    # host directly and other_host through the web vuln's service
    assert ws.host_false_positive_count == 2
    assert ws.service_false_positive_count == 1
    assert ws.vulnerability_triage_pending_count == 2


@pytest.mark.usefixtures('logged_user')
def test_dashboard_exposes_triage_stats(test_client, session, workspace_with_triage):
    update_workspace_vulns_count(workspace_id=workspace_with_triage.id)

    res = test_client.get(f'/v3/ws/{workspace_with_triage.name}')

    assert res.status_code == 200
    stats = res.json['stats']
    assert (stats['false_positive_vulns'], stats['triage_pending_vulns']) == (4, 2)
    assert (stats['std_vulns_false_positive'], stats['web_vulns_false_positive'],
            stats['code_vulns_false_positive']) == (2, 1, 1)
    assert (stats['critical_vulns_false_positive'], stats['high_vulns_false_positive'],
            stats['medium_vulns_false_positive'], stats['low_vulns_false_positive'],
            stats['info_vulns_false_positive'], stats['unclassified_vulns_false_positive']) == (1, 2, 0, 0, 1, 0)
    assert (stats['host_false_positive'], stats['service_false_positive']) == (2, 1)


def test_pipeline_triage_action_refreshes_counters(session, workspace):
    vuln = VulnerabilityFactory.create(workspace=workspace, status='open')
    session.commit()

    with mock.patch('faraday.server.utils.workflows.debounce_workspace_vulns_count_update') as debounce:
        _perform_triage_action([vuln.id], 'false_positive', True, user_id=None)

    debounce.assert_called_once_with(workspace_id=workspace.id)


def test_pipeline_action_without_changes_doesnt_refresh_counters(session, workspace):
    vuln = VulnerabilityFactory.create(workspace=workspace, status='open', confirmed=True, triaged=True)
    session.commit()

    with mock.patch('faraday.server.utils.workflows.debounce_workspace_vulns_count_update') as debounce:
        _perform_triage_action([vuln.id], 'confirmed', True, user_id=None)

    debounce.assert_not_called()
