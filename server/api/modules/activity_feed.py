# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import datetime
import time
from datetime import datetime

from flask import Blueprint
from marshmallow import fields

from server.api.base import AutoSchema, ReadWriteWorkspacedView, PaginatedMixin
from server.models import Command
from server.schemas import PrimaryKeyRelatedField

activityfeed_api = Blueprint('activityfeed_api', __name__)


class ActivityFeedSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    itime = fields.Method(serialize='get_itime', deserialize='load_itime', required=True, attribute='start_date')
    sum_created_vulnerabilities = fields.Method(serialize='get_sum_created_vulnerabilities', allow_none=True)
    sum_created_hosts = fields.Method(serialize='get_sum_created_hosts', allow_none=True)
    sum_created_services = fields.Method(serialize='get_sum_created_services', allow_none=True)
    sum_created_vulnerability_critical = fields.Method(serialize='get_sum_created_vulnerability_critical',
                                                       allow_none=True)
    workspace = PrimaryKeyRelatedField('name', dump_only=True)

    def load_itime(self, value):
        return datetime.datetime.fromtimestamp(value)

    def get_itime(self, obj):
        return time.mktime(obj.start_date.utctimetuple()) * 1000

    def get_sum_created_vulnerabilities(self, obj):
        return obj.sum_created_vulnerabilities

    def get_sum_created_hosts(self, obj):
        return obj.sum_created_hosts

    def get_sum_created_services(self, obj):
        return obj.sum_created_services

    def get_sum_created_vulnerability_critical(self, obj):
        return obj.sum_created_vulnerability_critical

    class Meta:
        model = Command
        fields = ('_id', 'command', 'ip', 'hostname',
                  'params', 'user', 'workspace', 'tool',
                  'import_source', 'itime', 'sum_created_vulnerabilities',
                  'sum_created_hosts', 'sum_created_services', 'sum_created_vulnerability_critical')


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
                'date': command['itime'],
            })
        return {
            'activities': commands,
        }


ActivityFeedView.register(activityfeed_api)
