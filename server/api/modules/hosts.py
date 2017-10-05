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
from server.models import Host, Service

host_api = Blueprint('host_api', __name__)


class HostSchema(AutoSchema):

    description = fields.String(required=True)  # Explicitly set required=True
    service_count = fields.Integer(dump_only=True)

    class Meta:
        model = Host
        fields = ('id', 'ip', 'description', 'os', 'service_count')


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
