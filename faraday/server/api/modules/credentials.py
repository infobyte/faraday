"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint
from marshmallow import fields, validate
from filteralchemy import FilterSet, operators  # pylint:disable=unused-import

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    FilterSetMeta,
    FilterAlchemyMixin,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
)
from faraday.server.models import Credential
from faraday.server.schemas import SelfNestedField, MetadataSchema

credentials_api = Blueprint('credentials_api', __name__)


class CredentialSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    owned = fields.Boolean(default=False, dump_only=True)
    username = fields.String(default='', required=True,
                             validate=validate.Length(min=1, error="Username must be defined"))
    password = fields.String(default='')
    endpoint = fields.String(default='')
    leak_date = fields.DateTime(allow_none=True)

    # for filtering
    metadata = SelfNestedField(MetadataSchema())

    class Meta:
        model = Credential


class CredentialFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Credential
        fields = (
            'username',
        )
        default_operator = operators.Equal
        operators = (operators.Equal, )


class CredentialView(FilterAlchemyMixin,
                     ReadWriteWorkspacedView,
                     BulkDeleteWorkspacedMixin,
                     BulkUpdateWorkspacedMixin):
    route_base = 'credential'
    model_class = Credential
    schema_class = CredentialSchema
    filterset_class = CredentialFilterSet

    def _envelope_list(self, objects, pagination_metadata=None):
        credentials = []
        for credential in objects:
            credentials.append({
                'id': credential['_id'],
                '_id': credential['_id'],
                'key': credential['_id'],
                'value': credential
            })
        return {
            'rows': credentials,
        }


CredentialView.register(credentials_api)
