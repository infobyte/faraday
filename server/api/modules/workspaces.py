# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import json

import flask
from flask import Blueprint
from flask_classful import route
from marshmallow import Schema, fields, post_load, validate
from sqlalchemy.orm import (
    query_expression,
    with_expression
)
from sqlalchemy.orm.exc import NoResultFound


from faraday.server.models import db, Workspace, _make_vuln_count_property
from faraday.server.schemas import (
    JSTimestampField,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from faraday.server.api.base import ReadWriteView, AutoSchema
from faraday.config.configuration import getInstanceConfiguration

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
    active = fields.Boolean(dump_only=True)

    create_date = fields.DateTime(attribute='create_date',
                           dump_only=True)

    update_date = fields.DateTime(attribute='update_date',
                           dump_only=True)


    class Meta:
        model = Workspace
        fields = ('_id', 'id', 'customer', 'description', 'active',
                  'duration', 'name', 'public', 'scope', 'stats',
                  'create_date', 'update_date', 'readonly')

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

    def index(self, **kwargs):
        query = self._get_base_query()
        objects = []
        for workspace_stat in query:
            workspace_stat = dict(workspace_stat)
            for key, value in workspace_stat.items():
                if key.startswith('workspace_'):
                    new_key = key.replace('workspace_', '')
                    workspace_stat[new_key] = workspace_stat[key]
            workspace_stat['scope'] = []
            if workspace_stat['scope_raw']:
                workspace_stat['scope_raw'] = workspace_stat['scope_raw'].split(',')
                for scope in workspace_stat['scope_raw']:
                    workspace_stat['scope'].append({'name': scope})
            objects.append(workspace_stat)
        return self._envelope_list(self._dump(objects, kwargs, many=True))

    def _get_querystring_boolean_field(self, field_name, default=None):
        try:
            val = bool(json.loads(flask.request.args[field_name]))
        except (KeyError, ValueError):
            val = default
        return val

    def _get_base_query(self, object_id=None):
        confirmed = self._get_querystring_boolean_field('confirmed')
        active = self._get_querystring_boolean_field('active')
        readonly = self._get_querystring_boolean_field('readonly')
        query = Workspace.query_with_count(
                confirmed,
                active=active,
                readonly=readonly,
                workspace_name=object_id)
        return query

    def _get_object(self, object_id, eagerload=False, **kwargs):
        """
        Given the object_id and extra route params, get an instance of
        ``self.model_class``
        """
        confirmed = self._get_querystring_boolean_field('confirmed')
        active = self._get_querystring_boolean_field('active')
        self._validate_object_id(object_id)
        query = db.session.query(Workspace).filter_by(name=object_id)
        if active is not None:
            query = query.filter_by(active=active)
        query = query.options(
                 with_expression(
                     Workspace.vulnerability_web_count,
                         _make_vuln_count_property('vulnerability_web',
                                          confirmed=confirmed,
                                          use_column_property=False),
                 ),
                 with_expression(
                     Workspace.vulnerability_standard_count,
                         _make_vuln_count_property('vulnerability',
                                          confirmed=confirmed,
                                          use_column_property=False)
                ),
                with_expression(
                     Workspace.vulnerability_total_count,
                         _make_vuln_count_property(type_=None,
                                          confirmed=confirmed,
                                          use_column_property=False)
               ),
               with_expression(
                     Workspace.vulnerability_code_count,
                    _make_vuln_count_property('vulnerability_code',
                                          use_column_property=False)
            ),


        )

        try:
            obj = query.one()
        except NoResultFound:
            flask.abort(404, 'Object with id "%s" not found' % object_id)
        return obj

    def _perform_create(self, data, **kwargs):
        scope = data.pop('scope', [])
        workspace = super(WorkspaceView, self)._perform_create(data, **kwargs)
        workspace.set_scope(scope)
        self._createWorkspaceFolder(workspace.name)
        db.session.commit()
        return workspace

    def _createWorkspaceFolder(self, name):
        CONF = getInstanceConfiguration()
        self._report_path = os.path.join(CONF.getReportPath(), name)
        self._report_ppath = os.path.join(self._report_path, "process")
        self._report_upath = os.path.join(self._report_path, "unprocessed")

        if not os.path.exists(CONF.getReportPath()):
            os.mkdir(CONF.getReportPath())

        if not os.path.exists(self._report_path):
            os.mkdir(self._report_path)

        if not os.path.exists(self._report_ppath):
            os.mkdir(self._report_ppath)

        if not os.path.exists(self._report_upath):
            os.mkdir(self._report_upath)

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

    @route('/<workspace_id>/activate/', methods=["PUT"])
    def activate(self, workspace_id):
        changed = self._get_object(workspace_id).activate()
        db.session.commit()
        return changed

    @route('/<workspace_id>/deactivate/', methods=["PUT"])
    def deactivate(self, workspace_id):
        changed = self._get_object(workspace_id).deactivate()
        db.session.commit()
        return changed

    @route('/<workspace_id>/change_readonly/', methods=["PUT"])
    def change_readonly(self, workspace_id):
        self._get_object(workspace_id).change_readonly()
        db.session.commit()
        return self._get_object(workspace_id).readonly


WorkspaceView.register(workspace_api)
