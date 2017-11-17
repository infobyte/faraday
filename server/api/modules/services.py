# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time

import flask
from flask import Blueprint
from marshmallow import fields, post_load, ValidationError
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import NoResultFound

from server.api.base import AutoSchema, ReadWriteWorkspacedView
from server.models import Host, Service, Workspace
from server.schemas import (
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
    port = fields.Integer(dump_only=True)  # Port is loaded via ports
    ports = MutableField(fields.String(),
                         fields.Method(deserialize='load_port'),
                         required=True,
                         attribute='port')
    status = fields.String(default='open')
    parent = fields.Integer(attribute='host_id', load_only=True)  # parent is not required for updates
    host_id = fields.Integer(attribute='host_id', dump_only=True)
    summary = fields.Method('get_summary')
    vulns = fields.Integer(attribute='vulnerability_count', dump_only=True)
    credentials = fields.Integer(attribute='credentials_count', dump_only=True)
    metadata = SelfNestedField(MetadataSchema())

    def load_port(self, value):
        # TODO migration: handle empty list and not numeric value
        return str(value.pop())

    def get_summary(self, obj):
        return "(%s/%s) %s" % (obj.port, obj.protocol, obj.name)

    @post_load
    def post_load_parent(self, data):
        """Gets the host_id from parent attribute. Pops it and tries to
        get a Host with that id in the corresponding workspace.
        """
        host_id = data.pop('host_id', None)
        if self.context['updating']:
            if host_id is None:
                # Partial update?
                return

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
                raise ValidationError('Host with id {} not found'.format(host_id))

    class Meta:
        model = Service
        fields = ('id', '_id', 'status', 'parent',
                  'protocol', 'description', '_rev',
                  'owned', 'owner', 'credentials', 'vulns',
                  'name', 'version', '_id', 'port', 'ports',
                  'metadata', 'summary', 'host_id')


class ServiceView(ReadWriteWorkspacedView):
    route_base = 'services'
    model_class = Service
    schema_class = ServiceSchema
    count_extra_filters = [Service.status == 'open']
    get_undefer = [Service.credentials_count, Service.vulnerability_count]

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

    def _get_base_query(self, workspace_name):
        original = super(ServiceView, self)._get_base_query(workspace_name)
        return original.options(
            joinedload(Service.credentials)
        )

ServiceView.register(services_api)
