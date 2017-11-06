# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time

import flask
from flask import Blueprint
from flask_classful import route
from marshmallow import fields

from server.api.base import AutoSchema, ReadWriteWorkspacedView
from server.utils.logger import get_logger
from server.utils.web import (
    gzipped,
    validate_workspace,
    filter_request_args, get_integer_parameter
)
from server.models import Command, Workspace

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

    @route('/activity_feed/')
    def activity_feed(self, workspace_name):
        res = []
        query = Command.query.join(Workspace).filter_by(name=workspace_name)
        for command in query.all():
            res.append({
                '_id': command.id,
                'user': command.user,
                'import_source': command.import_source,
                'command': command.command,
                'params': command.params,
                'vulnerabilities_count': (command.sum_created_vulnerabilities or 0) + (command.sum_created_vulnerabilities_web or 0),
                'hosts_count': command.sum_created_hosts or 0,
                'services_count': command.sum_created_services or 0,
                'criticalIssue': command.sum_created_vulnerability_critical or 0,
                'date': time.mktime(command.start_date.timetuple()) * 1000,

            })
        return res

CommandView.register(commandsrun_api)
