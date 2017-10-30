# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time

import flask
from flask import Blueprint
from marshmallow import fields

from server.api.base import AutoSchema, ReadWriteWorkspacedView
from server.utils.logger import get_logger
from server.utils.web import (
    gzipped,
    validate_workspace,
    filter_request_args, get_integer_parameter
)
from server.models import Command

commandsrun_api = Blueprint('commandsrun_api', __name__)


class CommandSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    itime = fields.Method('get_itime')
    duration = fields.Method('get_duration')
    workspace = fields.Method('get_workspace_name')

    def get_workspace_name(self, obj):
        return obj.workspace.name

    def get_itime(self, obj):
        return time.mktime(obj.start_date.utctimetuple())

    def get_duration(self, obj):
        if obj.end_date and obj.start_date:
            return (obj.end_date - obj.start_date).seconds

    class Meta:
        model = Command
        fields = ('_id', 'command', 'duration', 'itime', 'ip', 'hostname',
                  'params', 'user', 'workspace')


class CommandView(ReadWriteWorkspacedView):
    route_base = 'commands'
    model_class = Command
    schema_class = CommandSchema

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

CommandView.register(commandsrun_api)
