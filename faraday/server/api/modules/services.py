# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import Blueprint, abort, make_response, jsonify
from filteralchemy import FilterSet, operators  # pylint:disable=unused-import
from marshmallow import fields, post_load, ValidationError
from marshmallow.validate import OneOf, Range
from sqlalchemy.orm.exc import NoResultFound

from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    FilterSetMeta,
    FilterAlchemyMixin
)
from faraday.server.models import Host, Service, Workspace
from faraday.server.schemas import (
    MetadataSchema,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)


services_api = Blueprint('services_api', __name__)


class ServiceSchema(AutoSchema):
    _id = fields.Integer(attribute='id', dump_only=True)
    _rev = fields.String(default='', dump_only=True)
    owned = fields.Boolean(default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True,
                                   attribute='creator')
    port = fields.Integer(dump_only=True, required=True,
                          validate=[Range(min=0, error="The value must be greater than or equal to 0")])  # Port is loaded via ports
    ports = MutableField(fields.Integer(required=True,
                          validate=[Range(min=0, error="The value must be greater than or equal to 0")]),
                         fields.Method(deserialize='load_ports'),
                         required=True,
                         attribute='port')
    status = fields.String(missing='open', validate=OneOf(Service.STATUSES),
                           allow_none=False)
    parent = fields.Integer(attribute='host_id')  # parent is not required for updates
    host_id = fields.Integer(attribute='host_id', dump_only=True)
    vulns = fields.Integer(attribute='vulnerability_count', dump_only=True)
    credentials = fields.Integer(attribute='credentials_count', dump_only=True)
    metadata = SelfNestedField(MetadataSchema())
    type = fields.Function(lambda obj: 'Service', dump_only=True)
    summary = fields.String(dump_only=True)

    def load_ports(self, value):
        if not isinstance(value, list):
            raise ValidationError('ports must be a list')
        if len(value) != 1:
            raise ValidationError('ports must be a list with exactly one'
                                  'element')
        port = value.pop()
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                raise ValidationError('The value must be a number')
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

            if host_id != self.context['object'].parent.id:
                raise ValidationError('Can\'t change service parent.')

        else:
            if not host_id:
                raise ValidationError('Parent id is required when creating a service.')

            try:
                data['host'] = Host.query.join(Workspace).filter(
                    Workspace.name == self.context['workspace_name'],
                    Host.id == host_id
                ).one()
            except NoResultFound:
                raise ValidationError(f'Host with id {host_id} not found')

        return data

    class Meta:
        model = Service
        fields = ('id', '_id', 'status', 'parent', 'type',
                  'protocol', 'description', '_rev',
                  'owned', 'owner', 'credentials', 'vulns',
                  'name', 'version', '_id', 'port', 'ports',
                  'metadata', 'summary', 'host_id')


class ServiceFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Service
        fields = ('id', 'host_id', 'protocol', 'name', 'port')
        default_operator = operators.Equal
        operators = (operators.Equal,)


class ServiceView(FilterAlchemyMixin, ReadWriteWorkspacedView):

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
        }

    def _perform_create(self, data, **kwargs):
        port_number = data.get("port", "1")
        if not port_number.isdigit():
            abort(make_response(jsonify(message="Invalid Port number"), 400))
        return super()._perform_create(data, **kwargs)


ServiceView.register(services_api)
