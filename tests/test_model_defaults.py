"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
from datetime import date

# Related third party imports
import pytest

# Local application imports
from faraday.server.models import (
    SeveritiesHistogram,
    UserNotification,
    VulnerabilityHitCount,
    Workspace,
)


@pytest.mark.parametrize('column', [
    SeveritiesHistogram.date,
    VulnerabilityHitCount.date,
    UserNotification.event_date,
    Workspace.risk_history_total,
    Workspace.risk_history_avg,
])
def test_date_defaults_are_evaluated_on_each_insert(column):
    """A default like ``date.today()`` is evaluated once, when the module is
    imported, so every row gets the day the server started."""
    assert column.default.is_callable, f'{column} default is a fixed value, not evaluated per insert'


def test_new_workspace_risk_history_ends_today(session, workspace_factory):
    workspace = workspace_factory.create()
    session.commit()

    dates = [entry['date'] for entry in workspace.risk_history_total]
    assert dates[-1] == date.today().isoformat()
    assert dates == sorted(dates)  # oldest first, the order the risk history job appends in
    assert len(dates) == 30


def test_vulnerability_histogram_row_is_dated_today(session, vulnerability_factory):
    SeveritiesHistogram.query.delete()
    vuln = vulnerability_factory.create(severity='critical')
    session.commit()

    rows = SeveritiesHistogram.query.filter_by(workspace_id=vuln.workspace_id).all()
    assert [row.date for row in rows] == [date.today()]
