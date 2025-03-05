"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint
from marshmallow import fields

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
)
from faraday.server.models import Credential, db, VulnerabilityGeneric
from faraday.server.api.modules.vulns_base import VulnerabilitySchema
from faraday.server.schemas import SelfNestedField, MetadataSchema

credentials_api = Blueprint('credentials_api', __name__)


class CredentialSchema(AutoSchema):
    owned = fields.Boolean(default=False)
    username = fields.String(required=True)
    password = fields.String(required=True)
    endpoint = fields.String(required=True)
    leak_date = fields.DateTime(allow_none=True)

    vulnerabilities = fields.Function(
        serialize=lambda obj: (
            VulnerabilitySchema(many=True).dump(obj.vulnerabilities) if obj.vulnerabilities else []
        ),
        deserialize=lambda value: (
            db.session.query(VulnerabilityGeneric).filter(
                VulnerabilityGeneric.id.in_(value if isinstance(value, list) else [value])
            ).all() if value else []
        )
    )

    workspace_name = fields.String(attribute='workspace.name', dump_only=True)

    metadata = SelfNestedField(MetadataSchema())

    class Meta:
        model = Credential


class CredentialView(ReadWriteWorkspacedView,
                     BulkDeleteWorkspacedMixin,
                     BulkUpdateWorkspacedMixin):
    route_base = 'credential'
    model_class = Credential
    schema_class = CredentialSchema

    def _envelope_list(self, objects, pagination_metadata=None):
        credentials = []
        for credential in objects:
            credentials.append({
                'id': credential['id'],
                'key': credential['id'],
                'value': credential
            })
        return {
            'rows': credentials,
        }


CredentialView.register(credentials_api)
