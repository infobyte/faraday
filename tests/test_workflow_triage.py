from unittest import mock

import pytest

from faraday.server.api.modules.workflow import fields_lookup, rules_attributes
from faraday.server.models import VulnerabilityGeneric, VulnerabilityStatusHistory, db
from faraday.server.utils.workflows import _process_entry
from tests.factories import ActionFactory, VulnerabilityFactory
from tests.test_api_workflow import WORKFLOW_LIMIT, create_pipeline

pytestmark = [
    pytest.mark.usefixtures('logged_user'),
    pytest.mark.usefixtures('_workflow_limit'),
]


@pytest.fixture
def _workflow_limit():
    with mock.patch('faraday.server.api.modules.workflow.WORKFLOW_LIMIT', WORKFLOW_LIMIT):
        yield


def run_action(test_client, field, value, cond=None, **vuln_fields):
    action = ActionFactory.create(command="UPDATE", field=field, value=value)
    db.session.commit()
    ws, _, _, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability", cond=cond)
    vuln = VulnerabilityFactory.create(description="testing", workspace=ws, **vuln_fields)
    db.session.commit()
    _process_entry(vuln.__class__.__name__, [vuln.id], ws.id)
    db.session.expire_all()
    return VulnerabilityGeneric.query.get(vuln.id), pipeline


def test_false_positive_action(test_client, logged_user):
    vuln, pipeline = run_action(test_client, "false_positive", "true", status="open", confirmed=True, triaged=True)

    assert pipeline.creator_id == logged_user.id
    assert (vuln.confirmed, vuln.false_positive, vuln.triaged, vuln.status) == (False, True, True, 'closed')
    assert vuln.triaged_by_id == logged_user.id
    assert vuln.triaged_at is not None
    # This edition doesn't record the history
    assert VulnerabilityStatusHistory.query.filter_by(vulnerability_id=vuln.id).count() == 0


def test_risk_accepting_a_false_positive_confirms_it(test_client, logged_user):
    vuln, _ = run_action(test_client, "status", "risk-accepted", status="closed", false_positive=True, triaged=True)

    assert (vuln.confirmed, vuln.false_positive, vuln.triaged, vuln.status) == (True, False, True, 'risk-accepted')
    assert vuln.triaged_by_id == logged_user.id


def test_risk_accepting_triages_with_the_pipeline_creator(test_client, logged_user):
    vuln, _ = run_action(test_client, "status", "risk-accepted", status="open")

    assert (vuln.confirmed, vuln.triaged, vuln.triaged_by_id) == (False, True, logged_user.id)


def test_unconfirm_action(test_client):
    vuln, _ = run_action(test_client, "confirmed", "false", status="open", confirmed=True, triaged=True)

    assert (vuln.confirmed, vuln.triaged) == (False, False)


def test_reopen_false_positive(test_client):
    vuln, _ = run_action(test_client, "status", "re-opened", status="closed", false_positive=True, triaged=True)

    assert (vuln.false_positive, vuln.triaged, vuln.status) == (False, False, 're-opened')


@pytest.mark.parametrize('field, data, vuln_fields, applies', [
    ('false_positive', 'true', {'false_positive': True, 'status': 'closed'}, True),
    ('false_positive', 'true', {}, False),
    ('triaged', 'false', {}, True),
    ('triaged', 'false', {'triaged': True}, False),
])
def test_triage_conditions(test_client, field, data, vuln_fields, applies):
    cond = [{"type": "leaf", "field": field, "operator": "==", "data": data}]

    vuln, _ = run_action(test_client, "severity", "critical", cond=cond, severity="low", **vuln_fields)

    assert (vuln.severity == 'critical') == applies


def test_run_all_attributes_changes_to_the_pipeline_creator(test_client, logged_user):
    action = ActionFactory.create(command="UPDATE", field="false_positive", value="true")
    db.session.commit()
    ws, _, _, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
    vuln = VulnerabilityFactory.create(description="testing", workspace=ws, status="open")
    db.session.commit()

    _process_entry(None, None, ws.id, None, True, pipeline_id=pipeline.id)
    db.session.expire_all()

    vuln = VulnerabilityGeneric.query.get(vuln.id)
    assert (vuln.false_positive, vuln.triaged_by_id) == (True, logged_user.id)


def test_triage_fields_are_offered_to_pipelines():
    assert fields_lookup['vulnerability']['false_positive']['type'] == 'bool'
    condition_fields = {rule['name'] for rule in rules_attributes['vulnerability']}
    assert {'false_positive', 'triaged', 'triaged_at'} <= condition_fields
