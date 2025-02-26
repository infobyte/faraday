"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint
from marshmallow import fields, validate

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    FilterAlchemyMixin,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
)
from faraday.server.models import Credential
from faraday.server.schemas import SelfNestedField, MetadataSchema

credentials_api = Blueprint('credentials_api', __name__)


class CredentialSchema(AutoSchema):
    owned = fields.Boolean(default=False)
    username = fields.String(default='', required=True,
                             validate=validate.Length(min=1, error="Username must be defined"))
    password = fields.String(default='')
    endpoint = fields.String(default='')
    leak_date = fields.DateTime(allow_none=True)

    # for filtering
    metadata = SelfNestedField(MetadataSchema())

    class Meta:
        model = Credential


class CredentialView(FilterAlchemyMixin,
                     ReadWriteWorkspacedView,
                     BulkDeleteWorkspacedMixin,
                     BulkUpdateWorkspacedMixin):
    route_base = 'credential'
    model_class = Credential
    schema_class = CredentialSchema

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
