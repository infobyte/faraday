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

credentials_api = Blueprint('credentials_api', __name__)


class CredentialSchema(AutoSchema):
    owned = fields.Boolean(default=False)
    username = fields.String(required=True)
    password = fields.String(required=True)
    endpoint = fields.String(required=True)
    leak_date = fields.DateTime(allow_none=True)

    vulnerabilities = fields.List(fields.Nested(lambda: VulnerabilitySchema()), dump_only=True)
    vulnerabilities_ids = fields.List(fields.Integer(), load_only=True)

    workspace_name = fields.String(attribute='workspace.name', dump_only=True)

    class Meta:
        model = Credential


class CredentialView(ReadWriteWorkspacedView,
                     BulkDeleteWorkspacedMixin,
                     BulkUpdateWorkspacedMixin):
    route_base = 'credential'
    model_class = Credential
    schema_class = CredentialSchema

    def _perform_create(self, data, workspace_name):
        vuln_ids = data.pop('vulnerabilities_ids', None)
        if vuln_ids:
            vulns_to_add = db.session.query(VulnerabilityGeneric).filter(
                VulnerabilityGeneric.id.in_(vuln_ids)
            ).all()
            data['vulnerabilities'] = vulns_to_add
        return super()._perform_create(data, workspace_name)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False):
        vuln_ids = data.pop('vulnerabilities_ids', None)
        if vuln_ids:
            vulns_to_add = db.session.query(VulnerabilityGeneric).filter(
                VulnerabilityGeneric.id.in_(vuln_ids)
            ).all()
            data['vulnerabilities'] = vulns_to_add
        return super()._perform_update(object_id, obj, data, workspace_name, partial)

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
