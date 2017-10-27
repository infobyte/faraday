# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import json

import flask
from flask import Blueprint
from marshmallow import Schema, fields
from sqlalchemy.orm import undefer

from server.models import db, Workspace
from server.utils.logger import get_logger
from server.schemas import (
    JSTimestampField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from server.utils.web import (
    build_bad_request_response,
    filter_request_args,
    get_basic_auth,
    get_integer_parameter,
    gzipped,
    validate_admin_perm,
    validate_workspace
)
from server.couchdb import (
    list_workspaces_as_user,
    get_workspace
)
from server.api.base import ReadWriteView, AutoSchema

workspace_api = Blueprint('workspace_api', __name__)


class WorkspaceSummarySchema(Schema):
    credentials = fields.Integer(dump_only=True, attribute='credential_count')
    hosts = fields.Integer(dump_only=True, attribute='host_count')
    services = fields.Integer(dump_only=True, attribute='service_count')
    web_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_web_count')
    code_vulns = fields.Integer(dump_only=True, allow_none=False,
                                attribute='vulnerability_code_count')
    std_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_standard_count')
    total_vulns = fields.Integer(dump_only=True, allow_none=False,
                                 attribute='vulnerability_total_count')


class WorkspaceDurationSchema(Schema):
    start = JSTimestampField(attribute='start_date')
    end = JSTimestampField(attribute='end_date')


class WorkspaceSchema(AutoSchema):
    stats = SelfNestedField(WorkspaceSummarySchema())
    duration = SelfNestedField(WorkspaceDurationSchema())
    _id = fields.Integer(dump_only=True, attribute='id')
    scope = PrimaryKeyRelatedField('name', many=True, dump_only=True)

    class Meta:
        model = Workspace
        fields = ('_id', 'id', 'customer', 'description', 'active',
                  'duration', 'name', 'public', 'scope', 'stats')


class WorkspaceView(ReadWriteView):
    route_base = 'ws'
    lookup_field = 'name'
    lookup_field_type = unicode
    model_class = Workspace
    schema_class = WorkspaceSchema

    def _get_base_query(self):
        try:
            only_confirmed = bool(json.loads(flask.request.args['confirmed']))
        except (KeyError, ValueError):
            only_confirmed = False
        return Workspace.query_with_count(only_confirmed)


WorkspaceView.register(workspace_api)
