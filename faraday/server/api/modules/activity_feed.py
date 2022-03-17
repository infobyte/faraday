"""
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
from datetime import datetime

# Related third party imports
import pytz
from flask import Blueprint
from marshmallow import fields

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    PaginatedMixin,
)
from faraday.server.models import Command
from faraday.server.schemas import PrimaryKeyRelatedField

activityfeed_api = Blueprint('activityfeed_api', __name__)


class ActivityFeedSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    itime = fields.Method(serialize='get_itime', deserialize='load_itime', required=True, attribute='start_date')
    sum_created_vulnerabilities = fields.Method(serialize='get_sum_created_vulnerabilities', allow_none=True)
    sum_created_hosts = fields.Method(serialize='get_sum_created_hosts', allow_none=True)
    sum_created_services = fields.Method(serialize='get_sum_created_services', allow_none=True)
    sum_created_vulnerability_critical = fields.Integer(dump_only=True)
    sum_created_vulnerability_high = fields.Integer(dump_only=True)
    sum_created_vulnerability_medium = fields.Integer(dump_only=True)
    sum_created_vulnerability_low = fields.Integer(dump_only=True)
    sum_created_vulnerability_info = fields.Integer(dump_only=True)
    sum_created_vulnerability_unclassified = fields.Integer(dump_only=True)
    workspace = PrimaryKeyRelatedField('name', dump_only=True)
    creator = PrimaryKeyRelatedField('username', dump_only=True)

    @staticmethod
    def load_itime(value):
        return datetime.utcfromtimestamp(value)

    @staticmethod
    def get_itime(obj):
        return obj.start_date.replace(tzinfo=pytz.utc).timestamp() * 1000

    @staticmethod
    def get_sum_created_vulnerabilities(obj):
        return obj.sum_created_vulnerabilities

    @staticmethod
    def get_sum_created_hosts(obj):
        return obj.sum_created_hosts

    @staticmethod
    def get_sum_created_services(obj):
        return obj.sum_created_services

    class Meta:
        model = Command
        fields = ('_id', 'command', 'ip', 'hostname',
                  'params', 'user', 'workspace', 'tool',
                  'import_source', 'itime', 'sum_created_vulnerabilities',
                  'sum_created_hosts', 'sum_created_services',
                  'sum_created_vulnerability_critical', 'sum_created_vulnerability_high',
                  'sum_created_vulnerability_medium', 'sum_created_vulnerability_low',
                  'sum_created_vulnerability_info', 'sum_created_vulnerability_unclassified',
                  'creator')


class ActivityFeedView(PaginatedMixin, ReadWriteWorkspacedView):
    route_base = 'activities'
    model_class = Command
    schema_class = ActivityFeedSchema
    get_joinedloads = [Command.workspace]
    order_field = Command.start_date.desc()

    def _envelope_list(self, objects, pagination_metadata=None):
        commands = []
        for command in objects:
            commands.append({
                '_id': command['_id'],
                'user': command['user'],
                'import_source': command['import_source'],
                'command': command['command'],
                'tool': command['tool'],
                'params': command['params'],
                'vulnerabilities_count': (command['sum_created_vulnerabilities'] or 0),
                'hosts_count': command['sum_created_hosts'] or 0,
                'services_count': command['sum_created_services'] or 0,
                'criticalIssue': command['sum_created_vulnerability_critical'] or 0,
                'highIssue': command['sum_created_vulnerability_high'] or 0,
                'mediumIssue': command['sum_created_vulnerability_medium'] or 0,
                'lowIssue': command['sum_created_vulnerability_low'] or 0,
                'infoIssue': command['sum_created_vulnerability_info'] or 0,
                'unclassifiedIssue': command['sum_created_vulnerability_unclassified'] or 0,
                'date': command['itime'],
                'creator': command['creator']
            })
        return {
            'activities': commands,
        }


ActivityFeedView.register(activityfeed_api)
