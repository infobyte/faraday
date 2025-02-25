"""
Faraday Penetration Test IDE
Copyright (C) 2024  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from filteralchemy import FilterSet, operators
from flask import Blueprint
from marshmallow import ValidationError, fields, post_load
from marshmallow.validate import OneOf, Range
from sqlalchemy.orm.exc import NoResultFound

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    BulkDeleteMixin,
    BulkUpdateMixin,
    ContextMixin,
    FilterAlchemyMixin,
    FilterMixin,
    FilterSetMeta,
    PaginatedMixin,
    ReadOnlyView,
)
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.models import (
    Host,
    Service,
    Workspace,
    db,
)
from faraday.server.schemas import (
    MetadataSchema,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from faraday.server.utils.search import search
from faraday.server.utils.services import FILTER_SET_FIELDS, SCHEMA_FIELDS

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

    class Meta:
        model = Service
        fields = SCHEMA_FIELDS

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


class ServiceFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Service
        fields = FILTER_SET_FIELDS
        default_operator = operators.Equal
        operators = (operators.Equal,)


class ServiceView(
    PaginatedMixin,
    FilterMixin,
    FilterAlchemyMixin,
    ReadOnlyView,
    BulkDeleteMixin,
    BulkUpdateMixin,
    ContextMixin,
):

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

    def _perform_bulk_delete(self, values, **kwargs):
        workspaces = Workspace.query.join(Service).filter(Service.id.in_(values)).distinct(Workspace.name).all()
        response = super()._perform_bulk_delete(values, **kwargs)
        for workspace in workspaces:
            debounce_workspace_update(workspace.name)
        return response

    def _post_bulk_update(self, ids, extracted_data, data=None, **kwargs):
        workspaces = Workspace.query.join(Service).filter(Service.id.in_(ids)).distinct(Workspace.name).all()
        for workspace in workspaces:
            debounce_workspace_update(workspace.name)

    def _generate_filter_query(
            self, filters, severity_count=False, host_vulns=False, only_total_vulns=False, list_view=False
    ):

        filter_query = search(db.session, self.model_class, filters)

        filter_query = (self._apply_filter_context(filter_query).
                        filter(Service.workspace.has(active=True)))  # only services from active workspaces
        return filter_query


ServiceView.register(services_api)
