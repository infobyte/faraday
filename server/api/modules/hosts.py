# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from flask_classful import route
from marshmallow import fields
from filteralchemy import FilterSet, operators
from sqlalchemy.orm import undefer

from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace,\
    get_integer_parameter, filter_request_args
from server.dao.host import HostDAO
from server.api.base import (
    ReadWriteWorkspacedView,
    PaginatedMixin,
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
)
from server.schemas import PrimaryKeyRelatedField
from server.models import Host, Service

host_api = Blueprint('host_api', __name__)


class HostSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    id = fields.Integer()
    _rev = fields.String(default='')
    ip = fields.String(default='')
    description = fields.String(required=True)  # Explicitly set required=True
    credentials = fields.Function(lambda host: len(host.credentials))
    default_gateway = fields.List(fields.String, attribute="default_gateway_ip")
    metadata = fields.Method('get_metadata')
    name = fields.String(dump_only=True, attribute='ip', default='')
    os = fields.String(default='')
    owned = fields.Boolean(default=False)
    owner = PrimaryKeyRelatedField('username', attribute='creator')
    services = fields.Function(lambda host: len(host.services))
    vulns = fields.Function(lambda host: len(host.vulnerabilities))

    def get_metadata(self, obj):
        return {
            "command_id": None,
            "create_time": None,
            "creator": None,
            "owner": None,
            "update_action": None,
            "update_controller_action": None,
            "update_time":1504796508.21,
            "update_user": None
        }

    class Meta:
        model = Host
        fields = ('id', '_id', '_rev', 'ip', 'description',
                  'credentials', 'default_gateway', 'metadata',
                  'name', 'os', 'owned', 'owner', 'services', 'vulns'
                  )


class HostFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Host
        fields = ('os',)
        operators = (operators.Equal, operators.Like, operators.ILike)


class ServiceSchema(AutoSchema):

    class Meta:
        model = Service
        fields = ('id', 'name', 'description', 'port', 'protocol', 'status')


class HostsView(PaginatedMixin,
                FilterAlchemyMixin,
                ReadWriteWorkspacedView):
    route_base = 'hosts'
    model_class = Host
    schema_class = HostSchema
    unique_fields = ['ip']
    filterset_class = HostFilterSet

    @route('/<host_id>/services/')
    def service_list(self, workspace_name, host_id):
        services = self._get_object(host_id, workspace_name).services
        return ServiceSchema(many=True).dump(services).data

    def _get_base_query(self, workspace_name):
        """Get services_count in one query and not deferred, that doe
        one query per host"""
        original = super(HostsView, self)._get_base_query(workspace_name)
        return original.options(undefer(Host.service_count))

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
        }

HostsView.register(host_api)


@gzipped
@host_api.route('/ws/<workspace>/hosts', methods=['GET'])
def list_hosts(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    page = get_integer_parameter('page', default=0)
    page_size = get_integer_parameter('page_size', default=0)
    search = flask.request.args.get('search')
    order_by = flask.request.args.get('sort')
    order_dir = flask.request.args.get('sort_dir')

    host_filter = filter_request_args('page', 'page_size', 'search', 'sort', 'sort_dir')

    dao = HostDAO(workspace)
    result = dao.list(search=search,
                      page=page,
                      page_size=page_size,
                      order_by=order_by,
                      order_dir=order_dir,
                      host_filter=host_filter)

    return flask.jsonify(result)
