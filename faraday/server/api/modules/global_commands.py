# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time
import datetime
import logging

import pytz
from flask import Blueprint
from marshmallow import fields, post_load, ValidationError

from faraday.server.api.base import (
    AutoSchema,
    ReadOnlyView,
    PaginatedMixin
)
from faraday.server.models import Command
from faraday.server.schemas import MutableField, PrimaryKeyRelatedField, SelfNestedField, MetadataSchema

globalcommands_api = Blueprint('globalcommands_api', __name__)
logger = logging.getLogger(__name__)


def populate_command_dict(command):
    return {
                '_id': command.id,
                'user': command.user,
                'import_source': command.import_source,
                'command': command.command,
                'tool': command.tool,
                'params': command.params,
                'vulnerabilities_count': (command.sum_created_vulnerabilities or 0),
                'hosts_count': command.sum_created_hosts or 0,
                'services_count': command.sum_created_services or 0,
                'criticalIssue': command.sum_created_vulnerability_critical or 0,
                'date': time.mktime(command.start_date.timetuple()) * 1000,
            }


class SummarySchema(AutoSchema):
    description = fields.String()
    status = fields.Boolean()
    type = fields.String()
    target = fields.String()


class CommandSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    itime = fields.Method(serialize='get_itime', deserialize='load_itime', required=True, attribute='start_date')
    duration = MutableField(
        fields.Method(serialize='get_duration'),
        fields.Integer(),
        allow_none=True)
    workspace = PrimaryKeyRelatedField('name', dump_only=True)
    creator = PrimaryKeyRelatedField('username', dump_only=True)
    metadata = SelfNestedField(MetadataSchema())
    summary = SelfNestedField(SummarySchema())

    @staticmethod
    def load_itime(value):
        try:
            return datetime.datetime.utcfromtimestamp(value)
        except ValueError:
            raise ValidationError('Invalid Itime Value')

    @staticmethod
    def get_itime(obj):
        return obj.start_date.replace(tzinfo=pytz.utc).timestamp() * 1000

    @staticmethod
    def get_duration(obj):
        # obj.start_date can't be None
        if obj.end_date:
            return (obj.end_date - obj.start_date).seconds + ((obj.end_date - obj.start_date).microseconds / 1000000.0)
        else:
            if (datetime.datetime.utcnow() - obj.start_date).total_seconds() > 86400:  # 86400 is 1d TODO BY CONFIG
                return 'Timeout'
            return 'In progress'

    @post_load
    def post_load_set_end_date_with_duration(self, data, **kwargs):
        # there is a potential bug when updating, the start_date can be changed.
        duration = data.pop('duration', None)
        if duration:
            data['end_date'] = data['start_date'] + datetime.timedelta(
                seconds=duration)
        return data

    class Meta:
        model = Command
        fields = ('_id', 'command', 'duration', 'itime', 'ip', 'hostname',
                  'params', 'user', 'creator', 'workspace', 'tool', 'import_source', 'metadata')


class GlobalCommandView(ReadOnlyView, PaginatedMixin):
    route_base = 'global_commands'
    model_class = Command
    schema_class = CommandSchema
    order_field = Command.start_date.desc()

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
