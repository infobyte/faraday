"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import sys
import logging
import inspect
from queue import Queue

from sqlalchemy import event

from faraday.server.models import (
    Host,
    Service,
    TagObject,
    Comment,
    File,
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
