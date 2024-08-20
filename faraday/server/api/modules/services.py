"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import json
from json import JSONDecodeError

import flask
# Related third party imports
from flask import Blueprint, abort, make_response, jsonify, request
from filteralchemy import FilterSet, operators  # pylint:disable=unused-import
from flask_classful import route
from marshmallow import fields, post_load, ValidationError
from marshmallow.validate import OneOf, Range
from sqlalchemy.orm.exc import NoResultFound
from faraday.server.debouncer import debounce_workspace_update

# Local application imports
from faraday.server.models import (
    Host,
    Service,
    Workspace,
    db
)
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    PaginatedMixin,
    FilterSetMeta,
    FilterAlchemyMixin,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin, get_workspace, get_filtered_data
)
from faraday.server.schemas import (
    MetadataSchema,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from faraday.server.utils.command import set_command_id
from faraday.server.utils.filters import FlaskRestlessSchema
from faraday.server.utils.search import search

services_api = Blueprint('services_api', __name__)


class ServiceSchema(AutoSchema):
    _id = fields.Integer(attribute='id', dump_only=True)
    _rev = fields.String(default='', dump_only=True)
    owned = fields.Boolean(default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True,
                                   attribute='creator')
    # Port is loaded via ports
    port = fields.Integer(dump_only=True, required=True,
                          validate=[Range(min=0, error="The value must be greater than or equal to 0")])
    ports = MutableField(fields.Integer(required=True,
                                        validate=[Range(min=0, error="The value must be greater than or equal to 0")]),
                         fields.Method(deserialize='load_ports'),
                         required=True,
                         attribute='port')
    status = fields.String(missing='open', validate=OneOf(Service.STATUSES),
                           allow_none=False)
    parent = fields.Integer(attribute='host_id')  # parent is not required for updates
    parent_name = fields.String(attribute='host.ip', dump_only=True)
    host_id = fields.Integer(attribute='host_id', dump_only=True)
    vulns = fields.Integer(attribute='vulnerability_count', dump_only=True)
    credentials = fields.Integer(attribute='credentials_count', dump_only=True)
    metadata = SelfNestedField(MetadataSchema())
    type = fields.Function(lambda obj: 'Service', dump_only=True)
    summary = fields.String(dump_only=True)
    command_id = fields.Int(required=False, load_only=True)
    workspace_name = fields.String(attribute='workspace.name', dump_only=True)

    @staticmethod
    def load_ports(value):
        if not isinstance(value, list):
            raise ValidationError('ports must be a list')
        if len(value) != 1:
            raise ValidationError('ports must be a list with exactly one'
                                  'element')
        port = value.pop()
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError as e:
                raise ValidationError('The value must be a number') from e
        if port > 65535 or port < 1:
            raise ValidationError('The value must be in the range [1-65535]')

        return str(port)

    @post_load
    def post_load_parent(self, data, **kwargs):
        """Gets the host_id from parent attribute. Pops it and tries to
        get a Host with that id in the corresponding workspace.
        """
        host_id = data.pop('host_id', None)
        if self.context['updating']:
            if host_id is None:
                # Partial update?
                return data

            if 'object' in self.context:
                if host_id != self.context['object'].parent.id:
                    raise ValidationError('Can\'t change service parent.')
            else:
                if any(host_id != obj.parent.id for obj in self.context['objects']):
                    raise ValidationError('Can\'t change service parent.')

        else:
            if not host_id:
                raise ValidationError('Parent id is required when creating a service.')

            try:
                data['host'] = Host.query.join(Workspace).filter(
                    Workspace.name == self.context['workspace_name'],
                    Host.id == host_id
                ).one()
            except NoResultFound as e:
                raise ValidationError(f'Host with id {host_id} not found') from e

        return data

    class Meta:
        model = Service
        fields = ('id', '_id', 'status', 'parent', 'type',
                  'protocol', 'description', '_rev',
                  'owned', 'owner', 'credentials', 'vulns',
                  'name', 'version', '_id', 'port', 'ports',
                  'metadata', 'summary', 'host_id', 'command_id',
                  'workspace_name', 'parent_name')


class ServiceFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Service
        fields = ('id', 'host_id', 'protocol', 'name', 'port')
        default_operator = operators.Equal
        operators = (operators.Equal,)


class ServiceView(PaginatedMixin,
                  FilterAlchemyMixin,
                  ReadWriteWorkspacedView,
                  BulkDeleteWorkspacedMixin,
                  BulkUpdateWorkspacedMixin):

    route_base = 'services'
    model_class = Service
    schema_class = ServiceSchema
    count_extra_filters = [Service.status == 'open']
    get_undefer = [Service.credentials_count, Service.vulnerability_count]
    get_joinedloads = [Service.credentials, Service.update_user]
    filterset_class = ServiceFilterSet

    def _envelope_list(self, objects, pagination_metadata=None):
        services = []
        for service in objects:
            services.append({
                'id': service['_id'],
                'key': service['_id'],
                'value': service
            })
        return {
            'services': services,
            'count': (pagination_metadata.total
                      if pagination_metadata is not None else len(services))
        }

    def _perform_create(self, data, **kwargs):
        command_id = data.pop('command_id', None)
        port_number = data.get("port", "1")
        if not port_number.isdigit():
            abort(make_response(jsonify(message="Invalid Port number"), 400))
        obj = super()._perform_create(data, **kwargs)
        if command_id:
            set_command_id(db.session, obj, True, command_id)
        if kwargs['workspace_name']:
            debounce_workspace_update(kwargs['workspace_name'])
        return obj

    def _perform_bulk_delete(self, values, **kwargs):
        obj = super()._perform_bulk_delete(values, **kwargs)
        if kwargs['workspace_name']:
            debounce_workspace_update(kwargs['workspace_name'])
        return obj

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False):
        obj = super()._perform_update(object_id, obj, data, workspace_name=workspace_name, partial=partial)
        if workspace_name:
            debounce_workspace_update(workspace_name)
        return obj

    def _post_bulk_update(self, ids, extracted_data, workspace_name=None, data=None, **kwargs):
        if workspace_name:
            debounce_workspace_update(workspace_name)

    def _hostname_filters(self, filters):
        res_filters = []
        hostname_filters = []
        for search_filter in filters:
            if 'or' not in search_filter and 'and' not in search_filter:
                fieldname = search_filter.get('name')
                operator = search_filter.get('op')
                argument = search_filter.get('val')
                otherfield = search_filter.get('field')
                field_filter = {
                    "name": fieldname,
                    "op": operator,
                    "val": argument,

                }
                if otherfield:
                    field_filter.update({"field": otherfield})
                if fieldname == 'hostnames':
                    hostname_filters.append(field_filter)
                else:
                    res_filters.append(field_filter)
            elif 'or' in search_filter:
                or_filters, deep_hostname_filters = self._hostname_filters(search_filter['or'])
                if or_filters:
                    res_filters.append({"or": or_filters})
                hostname_filters += deep_hostname_filters
            elif 'and' in search_filter:
                and_filters, deep_hostname_filters = self._hostname_filters(search_filter['and'])
                if and_filters:
                    res_filters.append({"and": and_filters})
                hostname_filters += deep_hostname_filters

        return res_filters, hostname_filters

    @staticmethod
    def _generate_filter_query(model,
                               filters,
                               hostname_filters,
                               workspace,
                               marshmallow_params,
                               is_csv=False):
        hosts_os_filter = [host_os_filter for host_os_filter in filters.get('filters', []) if
                           host_os_filter.get('name') == 'host__os']

        if hosts_os_filter:
            # remove host__os filters from filters due to a bug
            hosts_os_filter = hosts_os_filter[0]
            filters['filters'] = [host_os_filter for host_os_filter in filters.get('filters', []) if
                                  host_os_filter.get('name') != 'host__os']

        services = search(db.session,
                          model,
                          filters)
        services = services.filter(Service.workspace == workspace)
        if hosts_os_filter:
            os_value = hosts_os_filter['val']
            services = services.join(Host).filter(Host.os == os_value)

        if 'group_by' not in filters:
            options = []
            if is_csv:
                options = options + []

            services = services.options(*options)
        return services

    def _filter(self, filters, workspace_name, exclude_list=None):
        hostname_filters = []
        services = None
        try:
            filters = FlaskRestlessSchema().load(json.loads(filters)) or {}
            if filters:
                filters['filters'], hostname_filters = self._hostname_filters(filters.get('filters', []))
        except (ValidationError, JSONDecodeError, AttributeError) as ex:
            flask.abort(400, "Invalid filters")

        workspace = get_workspace(workspace_name)
        marshmallow_params = {'many': True, 'context': {}}
        if 'group_by' not in filters:
            offset = None
            limit = None
            if 'offset' in filters:
                offset = filters.pop('offset')
            if 'limit' in filters:
                limit = filters.pop('limit')  # we need to remove pagination, since
            try:
                services = self._generate_filter_query(
                    Service,
                    filters,
                    hostname_filters,
                    workspace,
                    marshmallow_params,
                    bool(exclude_list))
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)
            # In services count we do not need order
            total_services = services.order_by(None)
            if limit:
                services = services.limit(limit)
            if offset:
                services = services.offset(offset)

            services = self.schema_class(**marshmallow_params).dump(services)
            return services, total_services.count()
        else:
            try:
                services = self._generate_filter_query(
                    Service,
                    filters,
                    hostname_filters,
                    workspace,
                    marshmallow_params,
                )
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)
            services_data, rows_count = get_filtered_data(filters, services)

            return services_data, rows_count

    @route('/filter')
    def filter(self, workspace_name):
        """
        ---
        get:
          tags: ["Filter", "Service"]
          description: Filters, sorts and groups services using a json with parameters. These parameters must be part of the model.
          parameters:
          - in: query
            name: q
            description: Recursive json with filters that supports operators. The json could also contain sort and group.
          responses:
            200:
              description: Returns filtered, sorted and grouped results
              content:
                application/json:
                  schema: FlaskRestlessSchema
            400:
              description: Invalid q was sent to the server
        tags: ["Filter", "Service"]
        responses:
          200:
            description: Ok
        """
        filters = request.args.get('q', '{}')
        filtered_services, count = self._filter(filters, workspace_name)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_services, pagination_metadata)


ServiceView.register(services_api)
