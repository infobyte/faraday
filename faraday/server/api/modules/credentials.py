"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import csv
from http import HTTPStatus
from io import TextIOWrapper, BytesIO
from logging import getLogger

# Related third party imports
from flask import Blueprint, request, make_response, abort, send_file
from werkzeug.exceptions import HTTPException
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
from sqlalchemy.exc import IntegrityError

credentials_api = Blueprint('credentials_api', __name__)
logger = getLogger(__name__)


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
            workspace = get_workspace(workspace_name)

            if vulns:
                valid_vulns = []
                for vuln in vulns:
                    if vuln.workspace_id == workspace.id:
                        valid_vulns.append(vuln)

                vulns = valid_vulns

            for credential_id in ids:
                credential = db.session.query(Credential).get(credential_id)
                if not credential:
                    continue

                if credential.workspace_id != workspace.id:
                    continue

                if not vulns:
                    continue

                for vuln in vulns:
                    if vuln not in credential.vulnerabilities:
                        credential.vulnerabilities.append(vuln)

                db.session.add(credential)
            db.session.commit()

        return super()._post_bulk_update(ids, extracted_data, workspace_name, data, **kwargs)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False, **kwargs):
        vulns = None
        if "vulnerabilities" in data:
            vulns = data.pop("vulnerabilities")
            workspace = get_workspace(workspace_name)

            if vulns:
                valid_vulns = []
                for vuln in vulns:
                    if vuln.workspace_id == workspace.id:
                        valid_vulns.append(vuln)

                vulns = valid_vulns

        obj = super()._perform_update(object_id, obj, data, workspace_name, partial)

        if vulns is not None:
            obj.vulnerabilities = vulns
            db.session.commit()

        return obj

    def _perform_create(self, data, workspace_name=None):
        vulns = None
        if "vulnerabilities" in data:
            vulns = data.pop("vulnerabilities")
            workspace = get_workspace(workspace_name)

            if vulns:
                valid_vulns = []
                for vuln in vulns:
                    if vuln.workspace_id == workspace.id:
                        valid_vulns.append(vuln)

                vulns = valid_vulns

        obj = super()._perform_create(data, workspace_name)

        if vulns is not None:
            obj.vulnerabilities = vulns
            db.session.commit()

        return obj

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
        logger.info("Importing credentials CSV for workspace %s", workspace_name)

        if request.form:
            vulns_ids = request.form.get('vulns_ids', "")
            # vulns need to come in string form, separated by commas
            if vulns_ids:
                vulns_ids = [int(vuln_id) for vuln_id in vulns_ids.split(',') if vuln_id.isdigit()]
        else:
            vulns_ids = []

        try:
            io_wrapper = TextIOWrapper(BytesIO(credentials_file.read()), encoding=request.content_encoding or "utf8")
            sample = io_wrapper.read(4096)
            if not sample.strip():
                abort(make_response({"message": "CSV file is empty"}, HTTPStatus.BAD_REQUEST))

            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=',;\t:|')
            except csv.Error:
                dialect = csv.excel

            first_row = next(csv.reader([sample.splitlines()[0]], dialect=dialect))
            first_row_fields = {f.strip().lower() for f in first_row}
            known_fields = {'username', 'password', 'endpoint', 'leak_date', 'owned'}
            has_header = bool(first_row_fields & known_fields)
            io_wrapper.seek(0)

            if has_header:
                credentials_reader = csv.DictReader(io_wrapper, skipinitialspace=True, dialect=dialect)
                missing_headers = {'username', 'password'}.difference(set(credentials_reader.fieldnames or []))
                if missing_headers:
                    abort(make_response(
                        {"message": f"Missing required headers in CSV: {missing_headers}"}, HTTPStatus.BAD_REQUEST
                    ))
            else:
                num_cols = len(first_row)
                if num_cols >= 3:
                    fieldnames = ['endpoint', 'username', 'password']
                elif num_cols == 2:
                    fieldnames = ['username', 'password']
                else:
                    abort(make_response(
                        {"message": "CSV must have at least 2 columns (username, password)"}, HTTPStatus.BAD_REQUEST
                    ))
                credentials_reader = csv.DictReader(io_wrapper, fieldnames=fieldnames, skipinitialspace=True, dialect=dialect)

            workspace = get_workspace(workspace_name)

            vulns = db.session.query(VulnerabilityGeneric).filter(
                VulnerabilityGeneric.id.in_(vulns_ids),
                VulnerabilityGeneric.workspace_id == workspace.id
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
                        endpoint=row.get('endpoint') or '',
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
                    logger.warning("Skipping duplicate credential '%s' in workspace %s", row.get('username', 'unknown'), workspace_name)
                    errors.append(f"Error importing credential {row.get('username', 'unknown')}: {str(e)}")
                except Exception as e:
                    logger.warning("Skipping credential '%s' in workspace %s: %s", row.get('username', 'unknown'), workspace_name, e)
                    errors.append(f"Error importing credential {row.get('username', 'unknown')}: {str(e)}")
                    skipped_credentials += 1

            logger.info("CSV import finished for workspace %s: created=%d, skipped=%d", workspace_name, created_credentials, skipped_credentials)
            return make_response({
                "message": f"CSV imported successfully - Created: {created_credentials} credentials, Skipped: {skipped_credentials} credentials",
                "errors": errors
            }, HTTPStatus.CREATED)

        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Error processing CSV file for workspace %s", workspace_name, exc_info=e)
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
                             download_name=f"Faraday-{workspace_name}-Credentials.csv",
                             as_attachment=True,
                             max_age=0)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count

        return self._envelope_list(filtered_creds, pagination_metadata)

    def _get_base_query(self, workspace_name):
        base_query = super()._get_base_query(workspace_name)
        return base_query.options(db.joinedload('vulnerabilities'))


CredentialView.register(credentials_api)
