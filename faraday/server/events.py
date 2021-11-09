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


def _create_or_update_histogram(session, workspace=None, medium=0, high=0, critical=0):
    if workspace is None:
        return

    sh = SeveritiesHistogram.query.filter(SeveritiesHistogram.date == date.today(),
                                          SeveritiesHistogram.workspace == workspace).first()
    if sh is None:
        sh = SeveritiesHistogram(workspace=workspace, medium=medium, high=high, critical=critical)
        session.add(sh)
    else:
        sh.medium += medium
        sh.high += high
        sh.critical += critical
        session.add(sh)


def _alter_severity_histogram_data_on_vuln_creation(session, instance):
    if instance.severity in SeveritiesHistogram.SEVERITIES_ALLOWED:
        medium = 1 if instance.severity == 'medium' else 0
        high = 1 if instance.severity == 'high' else 0
        critical = 1 if instance.severity == 'critical' else 0
        _create_or_update_histogram(session, workspace=instance.workspace, medium=medium, high=high, critical=critical)


def _alter_severity_histogram_data_on_vuln_update(session, instance):
    vuln_severity_history = get_history(instance, 'severity')

    # It's a recently created vuln or has no changes
    if vuln_severity_history.unchanged:
        return

    medium = high = critical = 0
    if vuln_severity_history.deleted[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
        medium = -1 if vuln_severity_history.deleted[0] == 'medium' else 0
        high = -1 if vuln_severity_history.deleted[0] == 'high' else 0
        critical = -1 if vuln_severity_history.deleted[0] == 'critical' else 0

    if vuln_severity_history.added[0] in SeveritiesHistogram.SEVERITIES_ALLOWED:
        medium = 1 if vuln_severity_history.added[0] == 'medium' else medium
        high = 1 if vuln_severity_history.added[0] == 'high' else high
        critical = 1 if vuln_severity_history.added[0] == 'critical' else critical

    _create_or_update_histogram(session, workspace=instance.workspace, medium=medium, high=high, critical=critical)


def update_severities_histogram(session, flush_context, other):
    # New vulnerabilities loaded
    for instance in session.new:
        if isinstance(instance, Vulnerability) or isinstance(instance, VulnerabilityWeb):
            _alter_severity_histogram_data_on_vuln_creation(session, instance)

    # Updated Vulns
    for instance in session.dirty:
        if isinstance(instance, Vulnerability) or isinstance(instance, VulnerabilityWeb):
            _alter_severity_histogram_data_on_vuln_update(session, instance)


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

# Update Severities Histogram
event.listen(db.session, "before_flush", update_severities_histogram)
