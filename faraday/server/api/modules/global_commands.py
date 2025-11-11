# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import logging

from celery.result import AsyncResult
from flask import Blueprint

from faraday.server.extensions import celery
from faraday.server.api.base import (
    ReadOnlyView,
    PaginatedMixin
)
from faraday.server.models import Command
from faraday.server.api.modules.commandsrun import CommandSchema

globalcommands_api = Blueprint('globalcommands_api', __name__)
logger = logging.getLogger(__name__)


def get_command_task_status(command: dict) -> list:
    """
    Retrieves the status of tasks associated with the given command.

    This function extracts tasks from the provided command dictionary and retrieves
    their respective statuses using asynchronous operations. The resulting list
    contains the status of each task, structured as dictionaries.

    Arguments:
        command (dict): A dictionary representing the command. Expects a 'tasks'
            key containing a list of task identifiers.

    Returns:
        list: A list of dictionaries where each dictionary maps a task identifier to
        its status. Returns an empty list if no tasks are found in the command.
    """
    _tasks = command.get('tasks', [])
    if not _tasks:
        return []
    task_status = []
    for task in _tasks:
        task_status.append({task: AsyncResult(task, app=celery).status})
    return task_status


class GlobalCommandView(ReadOnlyView, PaginatedMixin):
    route_base = 'global_commands'
    model_class = Command
    schema_class = CommandSchema
    order_field = Command.start_date.desc()

    def get(self, object_id, **kwargs):
        """
        Fetches and processes a command by its unique identifier.

        This method retrieves the specified command using its `object_id`, checks
        if it exists, and enriches it with task status information. If the command
        does not exist, it will return None.

        Args:
            object_id: Identifier of the command to be fetched.
            **kwargs: Additional keyword arguments to be passed to the parent `get` method.

        Returns:
            dict: A dictionary containing the command's information with task status
            appended, or None if the command does not exist.
        """
        command = super().get(object_id, **kwargs)
        if not command:
            return None
        command['tasks'] = get_command_task_status(command)
        return command

    def _envelope_list(self, objects, pagination_metadata=None):
        commands = []
        for command in objects:
            commands.append({
                'id': command['_id'],
                'key': command['_id'],
                'value': command
            })
        return {
            'commands': commands,
        }


GlobalCommandView.register(globalcommands_api)
