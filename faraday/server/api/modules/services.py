"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint, abort, make_response, jsonify
from filteralchemy import FilterSet, operators  # pylint:disable=unused-import
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
    BulkUpdateWorkspacedMixin
)
from faraday.server.schemas import (
    MetadataSchema,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from faraday.server.utils.command import set_command_id

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


class ServiceView(PaginatedMixin, FilterAlchemyMixin, ReadWriteWorkspacedView, BulkDeleteWorkspacedMixin, BulkUpdateWorkspacedMixin):

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


ServiceView.register(services_api)
