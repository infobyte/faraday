"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import sys
import logging
import inspect
from datetime import date
from queue import Queue

from sqlalchemy import event
from sqlalchemy.orm.attributes import get_history

from faraday.server.models import (
    Host,
    Service,
    TagObject,
    Comment,
    File,
    VulnerabilityWeb,
    SeveritiesHistogram,
    Vulnerability,
)
from faraday.server.models import db

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
    if workspace_id is None:
        logger.error("Workspace with None value. Histogram could not be updated")
        return
    ws_id = SeveritiesHistogram.query.with_entities('id').filter(
        SeveritiesHistogram.date == date.today(),
        SeveritiesHistogram.workspace_id == workspace_id).first()
    if ws_id is None:
        connection.execute(
            f"INSERT "  # nosec
            f"INTO severities_histogram (workspace_id, medium, high, critical, date, confirmed) "
            f"VALUES ({workspace_id}, {medium}, {high}, {critical}, '{date.today()}', {confirmed})")
    else:
        connection.execute(
            f"UPDATE severities_histogram "  # nosec
            f"SET medium = medium + {medium}, "
            f"high = high + {high}, "
            f"critical = critical + {critical}, "
            f"confirmed = confirmed + {confirmed}"
            f"WHERE id = {ws_id[0]}")


def _dicrease_severities_histogram(instance_severity, medium=0, high=0, critical=0):
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


def get_confirmed_value(instance) -> int:
    confirmed = get_history(instance, 'confirmed')
    if len(confirmed.unchanged) > 0:
        return 0
    if not confirmed.deleted or not confirmed.added:
        logger.error("Vuln confirmed history is None. Could not update confirmed value.")
        return 0
    if confirmed.deleted[0] is True:
        return -1
    else:
        return 1


def alter_histogram_on_update(mapper, connection, instance):
    confirmed = get_history(instance, 'confirmed')
    if len(confirmed.unchanged) > 0:
        confirmed_counter = 0
        confirmed_counter_on_close = -1 if confirmed.unchanged[0] is True else 0
    else:
        if not confirmed.deleted or not confirmed.added:
            logger.error("Vuln confirmed history is None. Could not update confirmed value.")
            return
        if confirmed.deleted[0] is True:
            confirmed_counter = -1
            confirmed_counter_on_close = confirmed_counter
        else:
            confirmed_counter = 1
            confirmed_counter_on_close = 0

    status = get_history(instance, 'status')
    if len(status.unchanged) > 0:
        vuln_severity_history = get_history(instance, 'severity')
        if len(vuln_severity_history.unchanged) > 0:
            if confirmed_counter != 0:
                _create_or_update_histogram(connection, instance.workspace_id, confirmed=confirmed_counter)
            return
        medium = high = critical = 0
        if not vuln_severity_history.deleted or not vuln_severity_history.added:
            if confirmed_counter != 0:
                _create_or_update_histogram(connection, instance.workspace_id, confirmed=confirmed_counter)
            logger.error("Vuln severity history is None. Could not update histogram.")
            return
        if vuln_severity_history.deleted[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _dicrease_severities_histogram(vuln_severity_history.deleted[0])

        if vuln_severity_history.added[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _increase_severities_histogram(instance.severity,
                                                                    medium=medium,
                                                                    high=high,
                                                                    critical=critical)
        _create_or_update_histogram(connection, instance.workspace_id, medium=medium, high=high, critical=critical, confirmed=confirmed)
    elif status.added[0] in [Vulnerability.STATUS_CLOSED, Vulnerability.STATUS_RISK_ACCEPTED]\
            and status.deleted[0] in [Vulnerability.STATUS_OPEN, Vulnerability.STATUS_RE_OPENED]:
        if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _dicrease_severities_histogram(instance.severity)
            _create_or_update_histogram(connection, instance.workspace_id, medium=medium, high=high,
                                        critical=critical, confirmed=confirmed_counter_on_close)
    elif status.added[0] in [Vulnerability.STATUS_OPEN, Vulnerability.STATUS_RE_OPENED] \
            and status.deleted[0] in [Vulnerability.STATUS_CLOSED, Vulnerability.STATUS_RISK_ACCEPTED]:
        if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _increase_severities_histogram(instance.severity)
            _create_or_update_histogram(connection, instance.workspace_id, medium=medium, high=high,
                                        critical=critical, confirmed=confirmed_counter)
    elif confirmed_counter != 0:
        _create_or_update_histogram(connection, instance.workspace_id, confirmed=confirmed_counter)


def alter_histogram_on_delete(mapper, connection, instance):
    if instance.status in [Vulnerability.STATUS_OPEN, Vulnerability.STATUS_RE_OPENED]:
        confirmed = -1 if instance.confirmed is True else 0
        if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _dicrease_severities_histogram(instance.severity)
            _create_or_update_histogram(connection, instance.workspace_id,
                                        medium=medium,
                                        high=high,
                                        critical=critical,
                                        confirmed=confirmed)


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
event.listen(Vulnerability, "before_insert", alter_histogram_on_insert)
event.listen(Vulnerability, "before_update", alter_histogram_on_update)
event.listen(Vulnerability, "before_delete", alter_histogram_on_delete)
event.listen(VulnerabilityWeb, "before_insert", alter_histogram_on_insert)
event.listen(VulnerabilityWeb, "before_update", alter_histogram_on_update)
event.listen(VulnerabilityWeb, "before_delete", alter_histogram_on_delete)
