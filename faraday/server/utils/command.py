import logging
import random
from datetime import datetime, timedelta

from faraday.server.api.base import InvalidUsage
from faraday.server.config import faraday_server
from faraday.server.models import (
    Command,
    CommandObject
)
from faraday.server.tasks import update_failed_command_stats

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


def schedule_update_failed_command_stats():
    delta_minutes = random.randint(5, 180)
    run_time = datetime.utcnow() + timedelta(minutes=delta_minutes)

    try:
        if faraday_server.celery_enabled:
            update_failed_command_stats.apply_async(eta=run_time)
            logger.info(f"Scheduled update_failed_command_stats at {run_time}")
        else:
            logger.info("Celery disabled, running update_failed_command_stats inline")
            update_failed_command_stats()
    except Exception as e:
        logger.error(f"Failed to schedule update_failed_command_stats: {e}")
