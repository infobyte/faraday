# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from flask_classful import route
from marshmallow import fields
from filteralchemy import FilterSet, operators
from sqlalchemy.orm import undefer, joinedload

from server.utils.database import get_or_create
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace,\
    get_integer_parameter, filter_request_args
from server.api.base import (
    ReadWriteWorkspacedView,
    PaginatedMixin,
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
)
from server.schemas import PrimaryKeyRelatedField
from server.models import Host, Service, db, Hostname

host_api = Blueprint('host_api', __name__)


class HostSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    id = fields.Integer()
    _rev = fields.String(default='')
    ip = fields.String(default='')
    description = fields.String(required=True)  # Explicitly set required=True
    default_gateway = fields.List(fields.String, attribute="default_gateway_ip")
    metadata = fields.Method('get_metadata')
    name = fields.String(dump_only=True, attribute='ip', default='')
    os = fields.String(default='')
    owned = fields.Boolean(default=False)
    owner = PrimaryKeyRelatedField('username', attribute='creator', dump_only=True)
    services = fields.Integer(attribute='open_service_count', dump_only=True)
    vulns = fields.Integer(attribute='vulnerability_count', dump_only=True)
    credentials = fields.Integer(attribute='credentials_count', dump_only=True)
    hostnames = PrimaryKeyRelatedField('name', many=True,
                                       attribute="hostnames",
                                       # TODO migration: make it writable
                                       dump_only=True,  # Only for now
                                       default=[])

    def get_metadata(self, obj):
        return {
            "command_id": None,
            "create_time": None,
            "creator": None,
            "owner": None,
            "update_action": None,
            "update_controller_action": None,
            "update_time": 1504796508.21,
            "update_user": None
        }

    class Meta:
        model = Host
        fields = ('id', '_id', '_rev', 'ip', 'description',
                  'credentials', 'default_gateway', 'metadata',
                  'name', 'os', 'owned', 'owner', 'services', 'vulns',
                  'hostnames'
                  )


class HostFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Host
        fields = ('os',)
        operators = (operators.Equal, operators.Like, operators.ILike)


class ServiceSchema(AutoSchema):
    vulns = fields.Integer(attribute='vulnerability_count', dump_only=True)

    class Meta:
        model = Service
        fields = ('id', 'name', 'description', 'port', 'protocol', 'status', 'vulns')


class HostsView(PaginatedMixin,
                FilterAlchemyMixin,
                ReadWriteWorkspacedView):
    route_base = 'hosts'
    model_class = Host
    order_field = Host.ip.asc()
    schema_class = HostSchema
    unique_fields = ['ip']
    filterset_class = HostFilterSet
    get_undefer = [Host.open_service_count,
                   Host.vulnerability_count]
    get_joinedloads = [Host.hostnames]

    @route('/<host_id>/services/')
    def service_list(self, workspace_name, host_id):
        services = self._get_object(host_id, workspace_name).services
        return ServiceSchema(many=True).dump(services).data

    def _perform_create(self, data, **kwargs):
        hostnames = data.pop('hostnames', [])
        default_gateway_ip = data.pop('default_gateway_ip', [None])
        host = super(HostsView, self)._perform_create(data, **kwargs)
        host.default_gateway_ip = default_gateway_ip[0]
        for name in hostnames:
            get_or_create(db.session, Hostname, name=name['key'], host=host,
                          workspace=host.workspace)
        db.session.commit()
        return host

    def _envelope_list(self, objects, pagination_metadata=None):
        hosts = []
        for host in objects:
            hosts.append({
                'id': host['id'],
                'key': host['id'],
                'value': host
            })
        return {
            'rows': hosts,
            'total_rows': (pagination_metadata and pagination_metadata.total
                           or len(hosts)),
        }

HostsView.register(host_api)
