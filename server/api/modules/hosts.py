# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from flask_classful import route
from marshmallow import fields
from filteralchemy import Filter, FilterSet, operators

from server.utils.database import get_or_create

from server.api.base import (
    ReadWriteWorkspacedView,
    PaginatedMixin,
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
)
from server.schemas import (
    MetadataSchema,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField
)
from server.models import Host, Service, db, Hostname
from server.api.modules.services import ServiceSchema

host_api = Blueprint('host_api', __name__)


class HostSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    id = fields.Integer()
    _rev = fields.String(default='')
    ip = fields.String(default='')
    description = fields.String(required=True)  # Explicitly set required=True
    default_gateway = fields.String(attribute="default_gateway_ip",
                                    required=False, allow_none=True)
    name = fields.String(dump_only=True, attribute='ip', default='')
    os = fields.String(default='')
    owned = fields.Boolean(default=False)
    owner = PrimaryKeyRelatedField('username', attribute='creator', dump_only=True)
    services = fields.Integer(attribute='open_service_count', dump_only=True)
    vulns = fields.Integer(attribute='vulnerability_count', dump_only=True)
    credentials = fields.Integer(attribute='credentials_count', dump_only=True)
    hostnames = MutableField(
        PrimaryKeyRelatedField('name', many=True,
                               attribute="hostnames",
                               dump_only=True,
                               default=[]),
        fields.List(fields.String))
    metadata = SelfNestedField(MetadataSchema())

    class Meta:
        model = Host
        fields = ('id', '_id', '_rev', 'ip', 'description', 'mac',
                  'credentials', 'default_gateway', 'metadata',
                  'name', 'os', 'owned', 'owner', 'services', 'vulns',
                  'hostnames'
                  )


class ServiceFilter(Filter):
    """Filter hosts by service name"""

    def filter(self, query, model, attr, value):
        return query.filter(model.services.any(Service.name == value))


class HostFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Host
        fields = ('os', 'service')
        operators = (operators.Equal, operators.Like, operators.ILike)
    service = ServiceFilter(fields.Str())


class HostsView(PaginatedMixin,
                FilterAlchemyMixin,
                ReadWriteWorkspacedView):
    route_base = 'hosts'
    model_class = Host
    order_field = Host.ip.asc()
    schema_class = HostSchema
    unique_fields = [('ip', )]
    filterset_class = HostFilterSet
    get_undefer = [Host.credentials_count,
                   Host.open_service_count,
                   Host.vulnerability_count]
    get_joinedloads = [Host.hostnames]

    @route('/<host_id>/services/')
    def service_list(self, workspace_name, host_id):
        services = self._get_object(host_id, workspace_name).services
        return ServiceSchema(many=True).dump(services).data

    def _perform_create(self, data, **kwargs):
        hostnames = data.pop('hostnames', [])
        host = super(HostsView, self)._perform_create(data, **kwargs)
        for name in hostnames:
            get_or_create(db.session, Hostname, name=name, host=host,
                          workspace=host.workspace)
        db.session.commit()
        return host

    def _update_object(self, obj, data):
        try:
            hostnames = data.pop('hostnames')
        except KeyError:
            pass
        else:
            obj.set_hostnames(hostnames)

        return super(HostsView, self)._update_object(obj, data)

    def _filter_query(self, query):
        query = super(HostsView, self)._filter_query(query)
        search_term = flask.request.args.get('search', None)
        if search_term is not None:
            like_term = '%' + search_term + '%'
            match_ip = Host.ip.ilike(like_term)
            match_service_name = Host.services.any(
                Service.name.ilike(like_term))
            match_hostname = Host.hostnames.any(Hostname.name.ilike(like_term))
            query = query.filter(match_ip |
                                 match_service_name |
                                 match_hostname)
        return query

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
