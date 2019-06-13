# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from flask_classful import route
from marshmallow import fields, Schema
from filteralchemy import Filter, FilterSet, operators

from faraday.server.utils.database import get_or_create

from faraday.server.api.base import (
    ReadWriteWorkspacedView,
    PaginatedMixin,
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
)
from faraday.server.schemas import (
    MetadataSchema,
    MutableField,
    NullToBlankString,
    PrimaryKeyRelatedField,
    SelfNestedField
)
from faraday.server.models import Host, Service, db, Hostname
from faraday.server.api.modules.services import ServiceSchema

host_api = Blueprint('host_api', __name__)


class HostSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    id = fields.Integer()
    _rev = fields.String(default='')
    ip = fields.String(default='')
    description = fields.String(required=True)  # Explicitly set required=True
    default_gateway = NullToBlankString(
        attribute="default_gateway_ip", required=False)
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
    type = fields.Function(lambda obj: 'Host', dump_only=True)
    service_summaries = fields.Method('get_service_summaries',
                                      dump_only=True)

    class Meta:
        model = Host
        fields = ('id', '_id', '_rev', 'ip', 'description', 'mac',
                  'credentials', 'default_gateway', 'metadata',
                  'name', 'os', 'owned', 'owner', 'services', 'vulns',
                  'hostnames', 'type', 'service_summaries'
                  )

    def get_service_summaries(self, obj):
        return [service.summary
                for service in obj.services
                if service.status == 'open']


class ServiceFilter(Filter):
    """Filter hosts by service name"""

    def filter(self, query, model, attr, value):
        return query.filter(model.services.any(Service.name == value))


class HostFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Host
        fields = ('ip', 'name', 'os', 'service')
        operators = (operators.Equal, operators.Like, operators.ILike)
    service = ServiceFilter(fields.Str())


class HostCountSchema(Schema):
    host_id = fields.Integer(dump_only=True, allow_none=False,
                                 attribute='id')
    critical = fields.Integer(dump_only=True, allow_none=False,
                                 attribute='vulnerability_critical_count')
    high = fields.Integer(dump_only=True, allow_none=False,
                              attribute='vulnerability_high_count')
    med = fields.Integer(dump_only=True, allow_none=False,
                              attribute='vulnerability_med_count')
    info = fields.Integer(dump_only=True, allow_none=False,
                              attribute='vulnerability_info_count')
    unclassified = fields.Integer(dump_only=True, allow_none=False,
                              attribute='vulnerability_unclassified_count')
    total = fields.Integer(dump_only=True, allow_none=False,
                                 attribute='vulnerability_total_count')

class HostsView(PaginatedMixin,
                FilterAlchemyMixin,
                ReadWriteWorkspacedView):
    route_base = 'hosts'
    model_class = Host
    order_field = Host.ip.asc()
    schema_class = HostSchema
    filterset_class = HostFilterSet
    get_undefer = [Host.credentials_count,
                   Host.open_service_count,
                   Host.vulnerability_count]
    get_joinedloads = [Host.hostnames, Host.services, Host.update_user]

    @route('/<host_id>/services/')
    def service_list(self, workspace_name, host_id):
        services = self._get_object(host_id, workspace_name).services
        return ServiceSchema(many=True).dump(services).data

    @route('/countVulns/')
    def count_vulns(self, workspace_name):
        host_ids = flask.request.args.get('hosts', None)
        if host_ids:
            host_id_list = host_ids.split(',')
        else:
            host_id_list = None

        res_dict = {'hosts':{}}

        host_count_schema = HostCountSchema()
        host_count = Host.query_with_count(None, host_id_list, workspace_name)

        for host in host_count.all():
            res_dict["hosts"][host.id] = host_count_schema.dump(host).data
        # return counts.data

        return res_dict

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

        # A commit is required here, otherwise it breaks (i'm not sure why)
        db.session.commit()

        return super(HostsView, self)._update_object(obj, data)

    def _filter_query(self, query):
        query = super(HostsView, self)._filter_query(query)
        search_term = flask.request.args.get('search', None)
        if search_term is not None:
            like_term = '%' + search_term + '%'
            match_ip = Host.ip.ilike(like_term)
            match_service_name = Host.services.any(
                Service.name.ilike(like_term))
            match_os = Host.os.ilike(like_term)
            match_hostname = Host.hostnames.any(Hostname.name.ilike(like_term))
            query = query.filter(match_ip |
                                 match_service_name |
                                 match_os |
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
