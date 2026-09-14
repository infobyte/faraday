import logging

from faraday.server.api.base import InvalidUsage
from faraday.server.models import (
    Command,
    CommandObject
)

logger = logging.getLogger(__name__)


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


def run_failed_command_stats_inline(app):
    """Run update_failed_command_stats without celery.

    Celery Beat schedules this task on celery deployments; when celery is
    disabled there is no scheduler, so the server runs it once on boot.
    The app context has to be pushed explicitly: celery only wraps tasks with
    one through ContextTask, which is installed by init_app and therefore
    missing when celery is disabled.
    """
    from faraday.server.tasks import update_failed_command_stats  # pylint: disable=import-outside-toplevel

    logger.info("Celery disabled, running update_failed_command_stats inline")
    try:
        with app.app_context():
            update_failed_command_stats()
    except Exception as e:
        logger.error(f"Failed to run update_failed_command_stats: {e}")
