"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import inspect
import logging
import sys
from queue import Queue

# Related third party imports
from sqlalchemy import event, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Query
from sqlalchemy.orm.attributes import get_history

# Local application imports
from faraday.server.models import (
    Host,
    Service,
    TagObject,
    Comment,
    File,
    SeveritiesHistogram,
    Vulnerability,
    VulnerabilityWeb,
    VulnerabilityGeneric,
    db,
)

logger = logging.getLogger(__name__)
changes_queue = Queue()


def new_object_event(mapper, connection, instance):
    # Since we don't have jet a model for workspace we
    # retrieve the name from the connection string
    try:
        name = instance.ip
    except AttributeError:
        name = instance.name
    msg = {
        'id': instance.id,
        'action': 'CREATE',
        'type': instance.__class__.__name__,
        'name': name,
        'workspace': instance.workspace.name
    }
    changes_queue.put(msg)


def delete_object_event(mapper, connection, instance):
    try:
        name = instance.ip
    except AttributeError:
        name = instance.name
    msg = {
        'id': instance.id,
        'action': 'DELETE',
        'type': instance.__class__.__name__,
        'name': name,
        'workspace': instance.workspace.name
    }
    db.session.query(TagObject).filter_by(
        object_id=instance.id,
        object_type=msg['type'].lower(),
    ).delete()
    db.session.query(Comment).filter_by(
        object_id=instance.id,
        object_type=msg['type'].lower(),
    ).delete()
    db.session.query(File).filter_by(
        object_id=instance.id,
        object_type=msg['type'].lower(),
    ).delete()
    changes_queue.put(msg)


def update_object_event(mapper, connection, instance):
    delta = instance.update_date - instance.create_date
    if delta.seconds < 30:
        # sometimes apis will commit to db to have fk.
        # this will avoid duplicate messages on websockets
        return
    name = getattr(instance, 'ip', None) or getattr(instance, 'name', None)
    msg = {
        'id': instance.id,
        'action': 'UPDATE',
        'type': instance.__class__.__name__,
        'name': name,
        'workspace': instance.workspace.name
    }
    changes_queue.put(msg)


def after_insert_check_child_has_same_workspace(mapper, connection, inserted_instance):
    if inserted_instance.parent:
        assert (inserted_instance.workspace
                == inserted_instance.parent.workspace), \
            "Conflicting workspace assignation for objects. " \
            "This should never happen!!!"

        assert (inserted_instance.workspace_id
                == inserted_instance.parent.workspace_id), \
            "Conflicting workspace_id assignation for objects. " \
            "This should never happen!!!"


def _create_or_update_histogram(connection, workspace_id=None, medium=0, high=0, critical=0, confirmed=0):
    logger.debug("Creating/Updating histogram ...")
    if workspace_id is None:
        logger.error("Workspace with None value. Histogram could not be updated")
        return
    histogram = {
        'workspace_id': workspace_id,
        'critical': critical,
        'high': high,
        'medium': medium,
        'confirmed': confirmed
    }
    stmt = postgresql.insert(SeveritiesHistogram).values(histogram)
    on_update_stmt = stmt.on_conflict_do_update(
        index_elements=[text('date'), text('workspace_id')],
        set_={
            "critical": text("severities_histogram.critical") + stmt.excluded.critical,
            "high": text("severities_histogram.high") + stmt.excluded.high,
            "medium": text("severities_histogram.medium") + stmt.excluded.medium,
            "confirmed": text("severities_histogram.confirmed") + stmt.excluded.confirmed
        }
    )
    connection.execute(on_update_stmt)


def _decrease_severities_histogram(instance_severity, medium=0, high=0, critical=0):
    medium = -1 if instance_severity == Vulnerability.SEVERITY_MEDIUM else medium
    high = -1 if instance_severity == Vulnerability.SEVERITY_HIGH else high
    critical = -1 if instance_severity == Vulnerability.SEVERITY_CRITICAL else critical

    return medium, high, critical


def _increase_severities_histogram(instance_severity, medium=0, high=0, critical=0):
    medium = 1 if instance_severity == Vulnerability.SEVERITY_MEDIUM else medium
    high = 1 if instance_severity == Vulnerability.SEVERITY_HIGH else high
    critical = 1 if instance_severity == Vulnerability.SEVERITY_CRITICAL else critical

    return medium, high, critical


def alter_histogram_on_insert(mapper, connection, instance):
    if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
        medium, high, critical = _increase_severities_histogram(instance.severity)
        confirmed = 1 if instance.confirmed else 0

        _create_or_update_histogram(connection,
                                    instance.workspace_id,
                                    medium=medium,
                                    high=high,
                                    critical=critical,
                                    confirmed=confirmed)


def alter_histogram_on_update(mapper, connection, instance):
    alter_histogram_on_update_general(connection,
                                      instance.workspace_id,
                                      status_history=get_history(instance, 'status'),
                                      confirmed_history=get_history(instance, 'confirmed'),
                                      severity_history=get_history(instance, 'severity'))


def alter_histogram_on_update_general(connection, workspace_id, status_history=None,
                                      confirmed_history=None, severity_history=None):

    if not status_history or not confirmed_history or not severity_history:
        logger.error("Not all history fields provided")
        return

    if len(confirmed_history.unchanged) > 0:
        confirmed_counter = 0
        confirmed_counter_on_close = -1 if confirmed_history.unchanged[0] is True else 0
        confirmed_counter_on_reopen = 1 if confirmed_history.unchanged[0] is True else 0
    else:
        if not confirmed_history.deleted or not confirmed_history.added:
            logger.error("Confirmed history deleted or added is None. Could not update confirmed value.")
            return
        if confirmed_history.deleted[0] is True:
            confirmed_counter = -1
            confirmed_counter_on_close = confirmed_counter
            confirmed_counter_on_reopen = 0
        else:
            confirmed_counter = 1
            confirmed_counter_on_close = 0
            confirmed_counter_on_reopen = confirmed_counter

    if len(status_history.unchanged) > 0:
        if len(severity_history.unchanged) > 0:
            if confirmed_counter != 0 and status_history.unchanged[0] in [Vulnerability.STATUS_OPEN,
                                                                          Vulnerability.STATUS_RE_OPENED]:
                _create_or_update_histogram(connection, workspace_id, confirmed=confirmed_counter)
            return
        medium = high = critical = 0
        if not severity_history.deleted or not severity_history.added:
            if confirmed_counter != 0 and status_history.unchanged[0] in [Vulnerability.STATUS_OPEN,
                                                                          Vulnerability.STATUS_RE_OPENED]:
                _create_or_update_histogram(connection, workspace_id, confirmed=confirmed_counter)
            logger.error("Severity history deleted or added is None. Could not update severity histogram.")
            return

        if severity_history.deleted[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _decrease_severities_histogram(severity_history.deleted[0])

        if severity_history.added[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _increase_severities_histogram(severity_history.added[0],
                                                                    medium=medium,
                                                                    high=high,
                                                                    critical=critical)
        _create_or_update_histogram(connection,
                                    workspace_id,
                                    medium=medium,
                                    high=high,
                                    critical=critical,
                                    confirmed=confirmed_counter)

    elif status_history.added[0] in [Vulnerability.STATUS_CLOSED, Vulnerability.STATUS_RISK_ACCEPTED]\
            and status_history.deleted[0] in [Vulnerability.STATUS_OPEN, Vulnerability.STATUS_RE_OPENED]:
        if len(severity_history.unchanged) > 0:
            severity = severity_history.unchanged[0]
        if len(severity_history.deleted) > 0:
            severity = severity_history.deleted[0]
        if severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _decrease_severities_histogram(severity)
            _create_or_update_histogram(connection, workspace_id, medium=medium, high=high,
                                        critical=critical, confirmed=confirmed_counter_on_close)
    elif status_history.added[0] in [Vulnerability.STATUS_OPEN, Vulnerability.STATUS_RE_OPENED] \
            and status_history.deleted[0] in [Vulnerability.STATUS_CLOSED, Vulnerability.STATUS_RISK_ACCEPTED]:
        if len(severity_history.unchanged) > 0:
            severity = severity_history.unchanged[0]
        if len(severity_history.added) > 0:
            severity = severity_history.added[0]
        if severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _increase_severities_histogram(severity)
            _create_or_update_histogram(connection, workspace_id, medium=medium, high=high,
                                        critical=critical, confirmed=confirmed_counter_on_reopen)
    elif confirmed_counter != 0:
        _create_or_update_histogram(connection, workspace_id, confirmed=confirmed_counter)


def alter_histogram_on_delete(mapper, connection, instance):
    if instance.status in [Vulnerability.STATUS_OPEN, Vulnerability.STATUS_RE_OPENED]:
        confirmed = -1 if instance.confirmed is True else 0
        if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _decrease_severities_histogram(instance.severity)
            _create_or_update_histogram(connection, instance.workspace_id,
                                        medium=medium,
                                        high=high,
                                        critical=critical,
                                        confirmed=confirmed)


def alter_histogram_on_before_compile_delete(query, delete_context):
    for desc in query.column_descriptions:
        if desc['type'] is Vulnerability or \
            desc['type'] is VulnerabilityGeneric or\
                desc['type'] is VulnerabilityWeb:
            instances = query.all()
            for instance in instances:
                if instance.status in [Vulnerability.STATUS_OPEN, Vulnerability.STATUS_RE_OPENED]:
                    if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
                        medium, high, critical = _decrease_severities_histogram(instance.severity)
                        _create_or_update_histogram(delete_context.session,
                                                    instance.workspace_id,
                                                    medium=medium,
                                                    high=high,
                                                    critical=critical,
                                                    confirmed=-1 if instance.confirmed is True else 0)


def get_history_from_context_values(context_values, field, old_value):
    field_history = type('history_dummy_class', (object,), {'added': [], 'unchanged': [old_value], 'deleted': []})()
    if field in context_values:
        if context_values[field] != old_value:
            field_history.deleted.append(old_value)
            field_history.added.append(context_values[field])
            field_history.unchanged.pop()
    return field_history


def alter_histogram_on_before_compile_update(query, update_context):
    for desc in query.column_descriptions:
        if desc['type'] is Vulnerability or \
            desc['type'] is VulnerabilityGeneric or\
                desc['type'] is VulnerabilityWeb:
            ids = [x[1] for x in filter(lambda x: x[0].startswith("id_"),
                                        query.statement.compile(dialect=postgresql.dialect()).params.items())]
            if ids:
                # this can arise some issues with counters when other filters were applied to query but...
                instances = update_context.session.query(VulnerabilityGeneric).filter(
                    VulnerabilityGeneric.id.in_(ids)).all()
            else:
                instances = query.all()

            for instance in instances:
                status_history = get_history_from_context_values(update_context.values, 'status', instance.status)
                severity_history = get_history_from_context_values(update_context.values, 'severity', instance.severity)
                confirmed_history = get_history_from_context_values(update_context.values, 'confirmed',
                                                                    instance.confirmed)

                alter_histogram_on_update_general(update_context.session,
                                                  instance.workspace_id,
                                                  status_history=status_history,
                                                  confirmed_history=confirmed_history,
                                                  severity_history=severity_history)


# register the workspace verification for all objs that has workspace_id
for name, obj in inspect.getmembers(sys.modules['faraday.server.models']):
    if inspect.isclass(obj) and getattr(obj, 'workspace_id', None):
        event.listen(obj, 'after_insert', after_insert_check_child_has_same_workspace)
        event.listen(obj, 'after_update', after_insert_check_child_has_same_workspace)


# Events for websockets
event.listen(Host, 'after_insert', new_object_event)
event.listen(Service, 'after_insert', new_object_event)

# Delete object bindings
event.listen(Host, 'after_delete', delete_object_event)
event.listen(Service, 'after_delete', delete_object_event)

# Update object bindings
event.listen(Host, 'after_update', update_object_event)
event.listen(Service, 'after_update', update_object_event)

# Severities Histogram
event.listen(VulnerabilityGeneric, "before_insert", alter_histogram_on_insert, propagate=True)
event.listen(VulnerabilityGeneric, "before_update", alter_histogram_on_update, propagate=True)
event.listen(VulnerabilityGeneric, "after_delete", alter_histogram_on_delete, propagate=True)
event.listen(Query, "before_compile_delete", alter_histogram_on_before_compile_delete)
event.listen(Query, "before_compile_update", alter_histogram_on_before_compile_update)
