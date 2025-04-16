"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint, request, make_response, abort, send_file
import csv
from io import TextIOWrapper
from marshmallow import fields

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    FilterWorkspacedMixin,
    get_workspace,
    route,
    PaginatedMixin,
)
from faraday.server.models import Credential, db, VulnerabilityGeneric
from faraday.server.api.modules.vulns_base import VulnerabilitySchema
from faraday.server.schemas import SelfNestedField, MetadataSchema
from faraday.server.utils.export import export_credentials_to_csv
from http import HTTPStatus
from sqlalchemy.exc import IntegrityError

credentials_api = Blueprint('credentials_api', __name__)


class CredentialSchema(AutoSchema):
    owned = fields.Boolean(default=False)
    username = fields.String(required=True, validate=lambda s: bool(s.strip()))
    password = fields.String(required=True, validate=lambda s: bool(s.strip()))
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
                     BulkUpdateWorkspacedMixin,
                     FilterWorkspacedMixin,
                     PaginatedMixin):
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
            'count': pagination_metadata.total if pagination_metadata is not None else len(credentials),
        }

    def _pre_bulk_update(self, data, **kwargs):
        vulns_to_add = []
        if "vulnerabilities" in data:
            vulns_to_add = data.pop("vulnerabilities")
        return {"vulnerabilities": vulns_to_add}

    def _post_bulk_update(self, ids, extracted_data, workspace_name=None, data=None, **kwargs):
        if "vulnerabilities" in extracted_data:
            vulns = extracted_data.pop("vulnerabilities")
            for credential_id in ids:
                credential = db.session.query(Credential).get(credential_id)
                if not credential:
                    continue
                for vuln in vulns:
                    if vuln not in credential.vulnerabilities:
                        credential.vulnerabilities.append(vuln)
                        db.session.add(credential)
            db.session.commit()

        return super()._post_bulk_update(ids, extracted_data, workspace_name, data, **kwargs)

    @route('/import_csv', methods=['POST'])
    def import_csv(self, workspace_name):
        """
        ---
        post:
          tags: ["Credential"]
          description: Import credentials from CSV
          responses:
            201:
              description: Created
        """
        if 'file' not in request.files:
            abort(make_response({"message": "No file provided."}, HTTPStatus.BAD_REQUEST))

        credentials_file = request.files['file']

        if request.form:
            vulns_ids = request.form.get('vulns_ids', "")
            # vulns need to come in string form, separated by commas
            if vulns_ids:
                vulns_ids = [int(vuln_id) for vuln_id in vulns_ids.split(',') if vuln_id.isdigit()]
        else:
            vulns_ids = []

        try:
            io_wrapper = TextIOWrapper(credentials_file, encoding=request.content_encoding or "utf8")
            credentials_reader = csv.DictReader(io_wrapper, skipinitialspace=True)

            required_headers = {'username', 'password', 'endpoint'}
            missing_headers = required_headers.difference(set(credentials_reader.fieldnames))
            if missing_headers:
                abort(
                    make_response(
                        {"message": f"Missing required headers in CSV: {missing_headers}"}, HTTPStatus.BAD_REQUEST
                    )
                )

            workspace = get_workspace(workspace_name)

            vulns = db.session.query(VulnerabilityGeneric).filter(
                VulnerabilityGeneric.id.in_(vulns_ids)
            ).all() if vulns_ids else []

            skipped_credentials = 0
            created_credentials = 0
            errors = []

            for row in credentials_reader:
                try:
                    owned = False

                    # Handle empty username and password
                    username = row.get('username')
                    password = row.get('password')
                    if username is None or username.strip() == '':
                        errors.append("Username cannot be empty")
                        skipped_credentials += 1
                        continue
                    if password is None or password.strip() == '':
                        errors.append(f"Password cannot be empty for username {username}")
                        skipped_credentials += 1
                        continue

                    # Handle empty leak_date
                    leak_date = row.get('leak_date')
                    leak_date = None if leak_date is None or leak_date.strip() == '' else leak_date

                    credential = Credential(
                        username=row['username'],
                        password=row['password'],
                        endpoint=row['endpoint'],
                        owned=owned,
                        leak_date=leak_date,
                        workspace=workspace
                    )

                    if vulns:
                        for vuln in vulns:
                            credential.vulnerabilities.append(vuln)

                    db.session.add(credential)
                    db.session.commit()
                    created_credentials += 1
                except IntegrityError as e:
                    db.session.rollback()
                    skipped_credentials += 1
                    errors.append(f"Error importing credential {row.get('username', 'unknown')}: {str(e)}")
                except Exception as e:
                    errors.append(f"Error importing credential {row.get('username', 'unknown')}: {str(e)}")

            return make_response({
                "message": f"CSV imported successfully - Created: {created_credentials} credentials, Skipped: {skipped_credentials} credentials",
                "errors": errors
            }, HTTPStatus.CREATED)

        except Exception as e:
            db.session.rollback()
            abort(make_response({"message": f"Error processing CSV file: {str(e)}"}, HTTPStatus.BAD_REQUEST))

    @route('/filter', methods=['GET'])
    def filter(self, workspace_name, **kwargs):
        """
        ---
        get:
          tags: ["Credential"]
          description: Filter Credentials
          responses:
            200:
              description: Credentials filtered successfully
            400:
              description: Bad Request
        """
        filters = request.args.get('q', '{}')
        export_csv = request.args.get('export_csv', '')
        filtered_creds, count = self._filter(filters, workspace_name)

        if export_csv.lower() == 'true':
            memory_file = export_credentials_to_csv(filtered_creds)
            return send_file(memory_file,
                             attachment_filename=f"Faraday-{workspace_name}-Credentials.csv",
                             as_attachment=True,
                             cache_timeout=-1)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count

        return self._envelope_list(filtered_creds, pagination_metadata)


CredentialView.register(credentials_api)
