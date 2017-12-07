import sys
import inspect

from sqlalchemy import event


def after_insert_check_child_has_same_workspace(mapper, connection, inserted_instance):
    if inserted_instance.parent:
        assert (inserted_instance.workspace ==
                inserted_instance.parent.workspace), \
                "Conflicting workspace assignation for objects. " \
                "This should never happen!!!"


# register the workspace verification for all objs that has workspace_id
for name, obj in inspect.getmembers(sys.modules['server.models']):
    if inspect.isclass(obj) and getattr(obj, 'workspace_id', None):
        event.listen(obj, 'after_insert', after_insert_check_child_has_same_workspace)
        event.listen(obj, 'after_update', after_insert_check_child_has_same_workspace)
