# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import json
import re

import flask
from flask import Blueprint
from marshmallow import Schema, fields, post_load, validate
from sqlalchemy.orm import undefer

from server.models import db, Workspace
from server.utils.logger import get_logger
from server.schemas import (
    JSTimestampField,
    MutableField,
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
    services = fields.Integer(dump_only=True,
                              attribute='total_service_count')
    web_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_web_count')
    code_vulns = fields.Integer(dump_only=True, allow_none=False,
                                attribute='vulnerability_code_count')
    std_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_standard_count')
    total_vulns = fields.Integer(dump_only=True, allow_none=False,
                                 attribute='vulnerability_total_count')


class WorkspaceDurationSchema(Schema):
    start_date = JSTimestampField(attribute='start_date')
    end_date = JSTimestampField(attribute='end_date')


class WorkspaceSchema(AutoSchema):

    name = fields.String(required=True,
                         validate=validate.Regexp(r"^[a-z0-9][a-z0-9\_\$\(\)\+\-\/]*$",0,"ERORROROR"))
    stats = SelfNestedField(WorkspaceSummarySchema())
    duration = SelfNestedField(WorkspaceDurationSchema())
    _id = fields.Integer(dump_only=True, attribute='id')
    scope = MutableField(
        PrimaryKeyRelatedField('name', many=True, dump_only=True),
        fields.List(fields.String)
    )

    create_date = fields.DateTime(attribute='create_date',
                           dump_only=True)

    update_date = fields.DateTime(attribute='update_date',
                           dump_only=True)


    class Meta:
        model = Workspace
        fields = ('_id', 'id', 'customer', 'description', 'active',
                  'duration', 'name', 'public', 'scope', 'stats',
                  'create_date', 'update_date')

    @post_load
    def post_load_duration(self, data):
        # Unflatten duration (move data[duration][*] to data[*])
        duration = data.pop('duration', None)
        if duration:
            data.update(duration)
        return data


class WorkspaceView(ReadWriteView):
    route_base = 'ws'
    lookup_field = 'name'
    lookup_field_type = unicode
    model_class = Workspace
    schema_class = WorkspaceSchema
    order_field = Workspace.name.asc()

    def _get_base_query(self):
        try:
            confirmed = bool(json.loads(flask.request.args['confirmed']))
        except (KeyError, ValueError):
            confirmed = None
        return Workspace.query_with_count(confirmed)

    def _perform_create(self, data, **kwargs):
        scope = data.pop('scope', [])
        workspace = super(WorkspaceView, self)._perform_create(data, **kwargs)
        workspace.set_scope(scope)
        db.session.commit()
        return workspace

    def _update_object(self, obj, data):
        scope = data.pop('scope', [])
        obj.set_scope(scope)
        return super(WorkspaceView, self)._update_object(obj, data)

    def _dump(self, obj, route_kwargs, **kwargs):
        # When the object was created or updated it doesn't have the stats
        # loaded so I have to query it again
        if not kwargs.get('many') and obj.vulnerability_total_count is None:
            obj = self._get_object(obj.name)
        return super(WorkspaceView, self)._dump(obj, route_kwargs, **kwargs)


WorkspaceView.register(workspace_api)
