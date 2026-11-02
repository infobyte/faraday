"""Vulnerability triage rules.

`triaged` is never written directly: it is derived from changes to `confirmed`,
`false_positive` and `status`, the same way regardless of where the change comes
from (API, pipelines or report import). Every write path goes through
apply_triage_rules (one vuln) or bulk_apply_triage (many vulns, Core UPDATE).
"""
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import Integer, bindparam, func, update
from sqlalchemy.dialects.postgresql import ARRAY

from faraday.server.models import (
    db,
    VulnerabilityGeneric,
    VulnerabilityStatusHistory,
)

logger = logging.getLogger(__name__)

STATUS_OPEN = VulnerabilityGeneric.STATUS_OPEN
STATUS_RE_OPENED = VulnerabilityGeneric.STATUS_RE_OPENED
STATUS_CLOSED = VulnerabilityGeneric.STATUS_CLOSED
STATUS_RISK_ACCEPTED = VulnerabilityGeneric.STATUS_RISK_ACCEPTED
OPEN_STATUSES = (STATUS_OPEN, STATUS_RE_OPENED)

SOURCE_MANUAL = 'manual'  # API and pipelines
SOURCE_IMPORT = 'import'  # report ingestion (bulk_create)

# Fields a request may change that feed the triage rules
TRIAGE_INPUT_FIELDS = ('confirmed', 'false_positive', 'status')

# History events, in the order they are recorded for a single action
EVENT_FIELDS = (
    VulnerabilityStatusHistory.FIELD_CONFIRMED,
    VulnerabilityStatusHistory.FIELD_FALSE_POSITIVE,
    VulnerabilityStatusHistory.FIELD_STATUS,
)


class TriageValidationError(ValueError):
    """The requested combination of changes contradicts the triage rules."""


@dataclass(frozen=True)
class TriageState:
    confirmed: bool
    false_positive: bool
    triaged: bool
    status: str

    @classmethod
    def from_vuln(cls, vuln):
        return cls(confirmed=bool(vuln.confirmed), false_positive=bool(vuln.false_positive),
                   triaged=bool(vuln.triaged), status=vuln.status)


@dataclass
class TriageResult:
    state: TriageState
    # Columns to write on the vuln: only the ones that change, plus triaged_by_id/triaged_at
    # when the action triaged the vuln
    values: dict = field(default_factory=dict)
    # (field, value) per changed field, in EVENT_FIELDS order
    events: list = field(default_factory=list)

    @property
    def changed(self):
        return bool(self.values)


# Columns the rules read and write. They're read with the row locked: two concurrent
# actions on the same vuln would otherwise both decide from the same state and each
# save only the fields it changed (e.g. one confirmed and the other false positive).
TRIAGE_STATE_COLUMNS = ('confirmed', 'false_positive', 'triaged', 'status', 'triaged_by_id', 'triaged_at')


def lock_triage_state(vuln):
    """Refresh `vuln`'s triage columns from the database, locking its row until the
    transaction ends, and return its TriageState.

    A concurrent action on the same vuln waits for this transaction, and this one
    decides from what the previous one saved. Refreshing (instead of only reading)
    also keeps the ORM from skipping a column it believes unchanged.
    """
    with db.session.no_autoflush:
        db.session.refresh(vuln, attribute_names=TRIAGE_STATE_COLUMNS, with_for_update=True)
    return TriageState.from_vuln(vuln)


def validate_triage_changes(changes):
    if changes.get('confirmed') is True and changes.get('false_positive') is True:
        raise TriageValidationError("A vulnerability can't be confirmed and a false positive at the same time")
    status = changes.get('status')
    if changes.get('false_positive') is True and status is not None and status != STATUS_CLOSED:
        raise TriageValidationError("Marking a vulnerability as false positive closes it, "
                                    f"it can't be set to status '{status}'")


def apply_triage_rules(current, changes, user_id=None, now=None, source=SOURCE_MANUAL):
    """Apply the triage rules to one vuln.

    `current` is a TriageState, `changes` holds the requested values of any of
    TRIAGE_INPUT_FIELDS (other keys are ignored). Only values that differ from
    `current` count as changes, so sending the whole vuln back is a no-op, and a
    full-body PUT that repeats the current values can't contradict itself.
    """
    now = now or datetime.utcnow()

    def requested(name):
        value = changes.get(name)
        if value is None or value == getattr(current, name):
            return None
        return value

    req_confirmed = requested('confirmed')
    req_false_positive = requested('false_positive')
    req_status = requested('status')
    # Validated after dropping the current values on purpose, not the raw `changes`: a
    # full-body PUT that marks a confirmed vuln as false positive sends confirmed=true
    # (its current value) with false_positive=true, which is a valid request. Bulk
    # bodies only carry the fields to change, so bulk_apply_triage also checks them raw.
    validate_triage_changes({'confirmed': req_confirmed, 'false_positive': req_false_positive, 'status': req_status})

    confirmed = current.confirmed
    false_positive = current.false_positive
    triaged = current.triaged
    status = current.status
    stamp = False  # the action triaged the vuln: record who and when

    if source == SOURCE_IMPORT:
        # Imports only change status. A false positive keeps its mark and stays closed.
        if req_status and not false_positive:
            if req_status == STATUS_CLOSED:
                stamp = True
            status = req_status
    elif req_false_positive is True:
        # Rules 2 and 3
        false_positive, confirmed, status, stamp = True, False, STATUS_CLOSED, True
    elif req_confirmed is True:
        # Rules 1, 3 and 4: confirming a false positive reopens it
        if false_positive:
            false_positive = False
            status = req_status if req_status and req_status != STATUS_CLOSED else STATUS_RE_OPENED
        elif req_status:
            status = req_status
        confirmed, stamp = True, True
    elif false_positive and req_status == STATUS_RISK_ACCEPTED:
        # Rule 5
        false_positive, confirmed, status, stamp = False, True, STATUS_RISK_ACCEPTED, True
    elif false_positive and (req_false_positive is False or req_status in OPEN_STATUSES):
        # Rule 4: reopening or removing the mark sends it back to the triage backlog
        false_positive, triaged = False, False
        status = req_status if req_status in OPEN_STATUSES else STATUS_RE_OPENED
    elif req_status and not false_positive:
        # Rule 6. Closing a false positive by hand is a no-op: it's already closed.
        status, stamp = req_status, True

    if stamp:
        triaged = True
    if req_confirmed is False and confirmed:
        # Rule 7: unconfirming always sends it back to the backlog
        confirmed, triaged, stamp = False, False, False

    state = TriageState(confirmed=confirmed, false_positive=false_positive, triaged=triaged, status=status)
    result = TriageResult(state=state)
    for name in ('confirmed', 'false_positive', 'triaged', 'status'):
        if getattr(state, name) != getattr(current, name):
            result.values[name] = getattr(state, name)
    if stamp:
        result.values['triaged_by_id'] = user_id
        result.values['triaged_at'] = now
    result.events = [(name, getattr(state, name)) for name in EVENT_FIELDS
                     if getattr(state, name) != getattr(current, name)]
    return result


def imported_vuln_triaged(confirmed, status):
    """Whether a vuln an import inserts starts triaged.

    A plugin that reports the vuln closed (or confirmed) has the same authority
    as a user doing it. Vulns that already exist follow apply_triage_rules with
    source=SOURCE_IMPORT, written as SQL in bulk_create.insert_vulnerabilities.
    """
    return bool(confirmed) or status == STATUS_CLOSED


def group_events(events_by_vuln):
    """`[[events, vuln_ids], ...]`, one entry per distinct list of events.

    A compact, JSON friendly form of `events_by_vuln` for Celery: a bulk action
    gives most vulns the same events. ungroup_events reverses it.
    """
    groups = defaultdict(list)
    for vuln_id, events in events_by_vuln.items():
        groups[tuple(tuple(event) for event in events)].append(vuln_id)
    return [[[list(event) for event in events], vuln_ids] for events, vuln_ids in groups.items()]


def ungroup_events(grouped_events):
    return {vuln_id: [tuple(event) for event in events]
            for events, vuln_ids in grouped_events for vuln_id in vuln_ids}


def build_history_rows(events_by_vuln, user_id, change_date):
    """VulnerabilityStatusHistory rows (as dicts) for the events of one action.

    Every row of the action shares `change_date`, so clients can group them.
    """
    rows = []
    for vuln_id, events in events_by_vuln.items():
        for name, value in events:
            row = {
                'vulnerability_id': vuln_id,
                'field': name,
                'status': None,
                'value': None,
                'user_id': user_id,
                'change_date': change_date,
            }
            if name == VulnerabilityStatusHistory.FIELD_STATUS:
                row['status'] = value
            else:
                row['value'] = value
            rows.append(row)
    return rows


@dataclass
class BulkTriageResult:
    # Only filled with bulk_apply_triage(track_events=True):
    # vuln id -> [(field, value), ...]
    events_by_vuln: dict = field(default_factory=dict)
    # vuln id -> new status, for the vulns whose status changed
    status_changes: dict = field(default_factory=dict)
    # vuln id -> status before the action, for the vulns whose status changed
    previous_status: dict = field(default_factory=dict)
    # ids of the vulns that changed at all
    updated_ids: list = field(default_factory=list)
    # how many of the requested vulns matched (changed or not)
    matched: int = 0


def _id_any(ids, param_name):
    # Same as faraday.server.api.base._id_in: one ARRAY param instead of one per id
    return VulnerabilityGeneric.id == func.any(bindparam(param_name, value=list(ids), type_=ARRAY(Integer)))


def bulk_apply_triage(ids, changes, user_id=None, now=None, source=SOURCE_MANUAL, extra_filters=(),
                      track_events=False):
    """Apply the triage rules to many vulns with as few UPDATEs as possible.

    Reads the current state of `ids` (narrowed by `extra_filters`, e.g. the
    permitted workspaces) locking their rows, computes each vuln's result and
    issues one UPDATE per distinct result. Doesn't commit.

    `track_events` also keeps, per changed vuln, its events, new status and previous
    status (see BulkTriageResult), for callers that record the history, recalculate
    risk or notify integrations. Off by default: on a large bulk they take memory.
    """
    changes = {name: changes[name] for name in TRIAGE_INPUT_FIELDS if changes.get(name) is not None}
    result = BulkTriageResult()
    if not ids or not changes:
        return result
    validate_triage_changes(changes)
    now = now or datetime.utcnow()

    query = db.session.query(
        VulnerabilityGeneric.id,
        VulnerabilityGeneric.confirmed,
        VulnerabilityGeneric.false_positive,
        VulnerabilityGeneric.triaged,
        VulnerabilityGeneric.status,
    ).filter(
        _id_any(ids, '_triage_ids'),
        *extra_filters,
    ).order_by(
        # The same lock order for every action, so two of them on overlapping vulns don't deadlock
        VulnerabilityGeneric.id,
    ).with_for_update()

    ids_by_values = defaultdict(list)
    for vuln_id, confirmed, false_positive, triaged, status in query:
        result.matched += 1
        current = TriageState(confirmed=confirmed, false_positive=false_positive, triaged=triaged, status=status)
        vuln_result = apply_triage_rules(current, changes, user_id=user_id, now=now, source=source)
        if not vuln_result.changed:
            continue
        ids_by_values[tuple(sorted(vuln_result.values.items()))].append(vuln_id)
        result.updated_ids.append(vuln_id)
        if track_events:
            result.events_by_vuln[vuln_id] = vuln_result.events
            if 'status' in vuln_result.values:
                result.status_changes[vuln_id] = vuln_result.values['status']
                result.previous_status[vuln_id] = status

    for values, group_ids in ids_by_values.items():
        stmt = update(VulnerabilityGeneric).where(_id_any(group_ids, '_triage_group_ids')).values(dict(values))
        db.session.execute(stmt, execution_options={'synchronize_session': False})
    logger.debug("Triage applied to %d vulns in %d updates", len(result.updated_ids), len(ids_by_values))
    return result
