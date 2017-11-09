# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import Blueprint
from marshmallow import fields, post_load, ValidationError
from filteralchemy import FilterSet, operators
from sqlalchemy.orm.exc import NoResultFound

from server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    FilterSetMeta,
    FilterAlchemyMixin, InvalidUsage)
from server.models import Credential, Host, Service, Workspace, db
from server.schemas import MutableField, SelfNestedField, MetadataSchema

credentials_api = Blueprint('credentials_api', __name__)


class CredentialSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    _rev = fields.String(default='', dump_only=True)
    owned = fields.Boolean(default=False)
    owner = fields.String(dump_only=True, attribute='creator.username', default='')
    username = fields.String(default='')
    password = fields.String(default='')
    description = fields.String(default='')
    couchdbid = fields.String(default='')  # backwards compatibility
    parent_type = MutableField(fields.Method('get_parent_type'),
                               fields.String(),
                               required=True)
    parent = MutableField(fields.Method('get_parent'),
                          fields.Integer(),
                          required=True)

    # for filtering
    host_id = fields.Integer(load_only=True)
    service_id = fields.Integer(load_only=True)
    metadata = SelfNestedField(MetadataSchema())

    def get_parent(self, obj):
        return obj.host_id or obj.service_id

    def get_parent_type(self, obj):
        assert obj.host_id is not None or obj.service_id is not None
        return 'Service' if obj.service_id is not None else 'Host'

    class Meta:
        model = Credential
        fields = ('id', '_id', "_rev", 'parent',
                  'username', 'description',
                  'name', 'password',
                  'owner', 'owned', 'couchdbid',
                  'parent', 'parent_type',
                  'metadata')

    @post_load
    def set_parent(self, data):
        parent_type = data.pop('parent_type', None)
        parent_id = data.pop('parent', None)
        if parent_type == 'Host':
            parent_class = Host
            parent_field = 'host_id'
        elif parent_type == 'Service':
            parent_class = Service
            parent_field = 'service_id'
        else:
            raise ValidationError(
                'Unknown parent type: {}'.format(parent_type))
        try:
            parent = db.session.query(parent_class).join(Workspace).filter(
                Workspace.name == self.context['workspace_name'],
                parent_class.id == parent_id).one()
        except NoResultFound:
            raise InvalidUsage('Parent id not found: {}'.format(parent_id))
        data[parent_field] = parent.id
        return data


class CredentialFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Credential
        fields = (
            'host_id',
            'service_id'
        )

        default_operator = operators.Equal
        operators = (operators.Equal, )


class CredentialView(FilterAlchemyMixin, ReadWriteWorkspacedView):
    route_base = 'credential'
    model_class = Credential
    schema_class = CredentialSchema
    filterset_class = CredentialFilterSet

    def _envelope_list(self, objects, pagination_metadata=None):
        credentials = []
        for credential in objects:
            credentials.append({
                'id': credential['_id'],
                'key': credential['_id'],
                'value': credential
            })
        return {
            'rows': credentials,
        }


CredentialView.register(credentials_api)
