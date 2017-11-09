# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time

import flask
from flask import Blueprint
from marshmallow import fields
from sqlalchemy.orm import joinedload

from server.api.base import AutoSchema, ReadWriteWorkspacedView
from server.models import Service
from server.schemas import MetadataSchema, SelfNestedField

services_api = Blueprint('services_api', __name__)


class ServiceSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    _rev = fields.String(default='', dump_only=True)
    owned = fields.Boolean(default=False)
    owner = fields.String(dump_only=True, attribute='creator.username')
    ports = fields.Method(attribute='port', deserialize='load_port')
    status = fields.String(default='open')
    parent = fields.Integer(attribute='host_id', load_only=True)
    host_id = fields.Integer(attribute='host_id', dump_only=True)
    summary = fields.Method('get_summary')
    metadata = SelfNestedField(MetadataSchema())

    def load_port(self, value):
        return str(value.pop())

    def get_summary(self, obj):
        return "(%s/%s) %s" % (obj.port, obj.protocol, obj.name)

    class Meta:
        model = Service
        fields = ('id', '_id', 'status', 'parent',
                  'protocol', 'description', '_rev',
                  'owned', 'owner', 'credentials',
                  'name', 'version', '_id', 'ports',
                  'metadata', 'summary', 'host_id')


class ServiceView(ReadWriteWorkspacedView):
    route_base = 'services'
    model_class = Service
    schema_class = ServiceSchema
    count_extra_filters = [Service.status == 'open']

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
