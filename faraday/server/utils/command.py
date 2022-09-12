from faraday.server.models import (
    Command,
    CommandObject
)
from faraday.server.api.base import InvalidUsage


def set_command_id(session, obj, created, command_id):
    command = session.query(Command).filter(
        Command.id == command_id,
        Command.workspace == obj.workspace
    ).first()
    if command is None:
        raise InvalidUsage('Command not found.')
    # if the object is created and updated in the same command
    # the command object already exists
    # we skip the creation.
    object_type = obj.__class__.__table__.name

    command_object = CommandObject.query.filter_by(
        object_id=obj.id,
        object_type=object_type,
        command=command,
        workspace=obj.workspace,
    ).first()
    if created or not command_object:
        command_object = CommandObject(
            object_id=obj.id,
            object_type=object_type,
            command=command,
            workspace=obj.workspace,
            created_persistent=created
        )

    session.add(command)
    session.add(command_object)
