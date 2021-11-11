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


def _create_or_update_histogram(connection, workspace_id=None, medium=0, high=0, critical=0):
    if workspace_id is None:
        return
    ws_id = SeveritiesHistogram.query.with_entities('id').filter(
        SeveritiesHistogram.date == date.today(),
        SeveritiesHistogram.workspace_id == workspace_id).first()
    if ws_id is None:
        connection.execute(
            f"INSERT "
            f"INTO severities_histogram (workspace_id, medium, high, critical, date) "
            f"VALUES ({workspace_id}, {medium}, {high}, {critical}, '{date.today()}')")
    else:
        connection.execute(
            f"UPDATE severities_histogram "
            f"SET medium = medium + {medium}, high = high + {high}, critical = critical + {critical} "
            f"WHERE id = {ws_id[0]}")


def _dicrease_severities_histogram(instance_severity, medium=0, high=0, critical=0):
    medium = -1 if instance_severity == 'medium' else medium
    high = -1 if instance_severity == 'high' else high
    critical = -1 if instance_severity == 'critical' else critical

    return medium, high, critical


def _increase_severities_histogram(instance_severity, medium=0, high=0, critical=0):
    medium = 1 if instance_severity == 'medium' else medium
    high = 1 if instance_severity == 'high' else high
    critical = 1 if instance_severity == 'critical' else critical

    return medium, high, critical


def alter_histogram_on_insert(mapper, connection, instance):
    if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
        medium, high, critical = _increase_severities_histogram(instance.severity)
        _create_or_update_histogram(connection, instance.workspace.id, medium=medium, high=high, critical=critical)


def alter_histogram_on_update(mapper, connection, instance):
    status = get_history(instance, 'status')
    if len(status.unchanged) > 0:
        vuln_severity_history = get_history(instance, 'severity')
        if len(vuln_severity_history.unchanged) > 0:
            return
        medium = high = critical = 0
        if vuln_severity_history.deleted and vuln_severity_history.deleted[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _dicrease_severities_histogram(vuln_severity_history.deleted[0])

        if vuln_severity_history.added and vuln_severity_history.added[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _increase_severities_histogram(instance.severity,
                                                                    medium=medium,
                                                                    high=high,
                                                                    critical=critical)
        _create_or_update_histogram(connection, instance.workspace.id, medium=medium, high=high, critical=critical)
    else:
        if status.added[0] == 'closed':
            if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
                medium, high, critical = _dicrease_severities_histogram(instance.severity)
                _create_or_update_histogram(connection, instance.workspace.id, medium=medium, high=high,
                                            critical=critical)
        elif status.deleted[0] == 'closed':
            if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
                medium, high, critical = _increase_severities_histogram(instance.severity)
                _create_or_update_histogram(connection, instance.workspace.id, medium=medium, high=high,
                                            critical=critical)


def alter_histogram_on_delete(mapper, connection, instance):
    if instance.status != 'closed':
        if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
            medium, high, critical = _dicrease_severities_histogram(instance.severity)
            _create_or_update_histogram(connection, instance.workspace.id, medium=medium, high=high,
                                         critical=critical)


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
