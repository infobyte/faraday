# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import re
from builtins import str

import json
import logging

import flask
from flask import Blueprint, abort, make_response, jsonify
from flask_classful import route
from marshmallow import Schema, fields, post_load, ValidationError
from sqlalchemy.orm import (
    with_expression
)
from sqlalchemy.orm.exc import NoResultFound


from faraday.server.models import db, Workspace, _make_vuln_count_property, Vulnerability, \
    _make_active_agents_count_property, count_vulnerability_severities
from faraday.server.schemas import (
    JSTimestampField,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from faraday.server.api.base import ReadWriteView, AutoSchema, FilterMixin

logger = logging.getLogger(__name__)

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
    critical_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_critical_count')
    info_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_informational_count')
    high_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_high_count')
    medium_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_medium_count')
    low_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_low_count')
    unclassified_vulns = fields.Integer(dump_only=True, allow_none=False,
                               attribute='vulnerability_unclassified_count')
    total_vulns = fields.Integer(dump_only=True, allow_none=False,
                                 attribute='vulnerability_total_count')


class WorkspaceDurationSchema(Schema):
    start_date = JSTimestampField(attribute='start_date')
    end_date = JSTimestampField(attribute='end_date')


def validate_workspace_name(name):
    blacklist = ["filter"]
    if name in blacklist:
        raise ValidationError(f"Not possible to create workspace of name: {name}")
    if not re.match(r"^[a-z0-9][a-z0-9_$()+-]*$", name):
        raise ValidationError("The workspace name must validate with the regex "
                              "^[a-z0-9][a-z0-9_$()+-]*$")


class WorkspaceSchema(AutoSchema):

    name = fields.String(required=True, validate=validate_workspace_name)
    stats = SelfNestedField(WorkspaceSummarySchema())
    duration = SelfNestedField(WorkspaceDurationSchema())
    _id = fields.Integer(dump_only=True, attribute='id')
    scope = MutableField(
        PrimaryKeyRelatedField('name', many=True, dump_only=True),
        fields.List(fields.String)
    )
    active = fields.Boolean()

    create_date = fields.DateTime(attribute='create_date',
                           dump_only=True)

    update_date = fields.DateTime(attribute='update_date',
                           dump_only=True)

    active_agents_count = fields.Integer(dump_only=True)

    class Meta:
        model = Workspace
        fields = ('_id', 'id', 'customer', 'description', 'active',
                  'duration', 'name', 'public', 'scope', 'stats',
                  'create_date', 'update_date', 'readonly',
                  'active_agents_count')

    @post_load
    def post_load_duration(self, data, **kwargs):
        # Unflatten duration (move data[duration][*] to data[*])
        duration = data.pop('duration', None)
        if duration:
            data.update(duration)
        if 'start_date' in data and 'end_date' in data and data['start_date'] and data['end_date']:
            if data['start_date'] > data['end_date']:
                raise ValidationError("start_date is bigger than end_date.")
        return data


class WorkspaceView(ReadWriteView, FilterMixin):
    route_base = 'ws'
    lookup_field = 'name'
    lookup_field_type = str
    model_class = Workspace
    schema_class = WorkspaceSchema
    order_field = Workspace.name.asc()

    def index(self, **kwargs):
        """
          ---
          get:
            summary: "Get a list of workspaces."
            tags: ["Workspace"]
            responses:
              200:
                description: Ok
                content:
                  application/json:
                    schema: WorkspaceSchema
          tags: ["Workspace"]
          responses:
            200:
              description: Ok
        """
        query = self._get_base_query()
        objects = []
        for workspace_stat in query:
            workspace_stat_dict = dict(workspace_stat)
            for key, _ in list(workspace_stat_dict.items()):
                if key.startswith('workspace_'):
                    new_key = key.replace('workspace_', '')
                    workspace_stat_dict[new_key] = workspace_stat_dict[key]
            workspace_stat_dict['scope'] = []
            if workspace_stat_dict['scope_raw']:
                workspace_stat_dict['scope_raw'] = workspace_stat_dict['scope_raw'].split(',')
                for scope in workspace_stat_dict['scope_raw']:
                    workspace_stat_dict['scope'].append({'name': scope})
            objects.append(workspace_stat_dict)
        return self._envelope_list(self._dump(objects, kwargs, many=True))

    @route('/filter')
    def filter(self):
        """
        ---
            tags: ["Filter"]
            summary: Filters, sorts and groups objects using a json with parameters.
            parameters:
            - in: query
              name: q
              description: recursive json with filters that supports operators. The json could also contain sort and group

            responses:
              200:
                description: return filtered, sorted and grouped results
                content:
                  application/json:
                    schema: FlaskRestlessSchema
              400:
                description: invalid q was sent to the server

        """
        filters = flask.request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters, severity_count=True, host_vulns=False)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_objs, pagination_metadata)

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
        status = flask.request.args.get('status')

        extra_query = None
        if status and status in Vulnerability.STATUSES:
            extra_query = f"status='{status}'"

        self._validate_object_id(object_id)
        query = db.session.query(Workspace).filter_by(name=object_id)
        if active is not None:
            query = query.filter_by(active=active)
        query = query.options(
                 with_expression(
                     Workspace.vulnerability_web_count,
                         _make_vuln_count_property('vulnerability_web',
                                          confirmed=confirmed,
                                          extra_query=extra_query,
                                          use_column_property=False),
                 ),
                 with_expression(
                     Workspace.vulnerability_standard_count,
                         _make_vuln_count_property('vulnerability',
                                          confirmed=confirmed,
                                          extra_query=extra_query,
                                          use_column_property=False)
                ),
                with_expression(
                     Workspace.vulnerability_total_count,
                         _make_vuln_count_property(type_=None,
                                          confirmed=confirmed,
                                          extra_query=extra_query,
                                          use_column_property=False)
               ),
               with_expression(
                     Workspace.vulnerability_code_count,
                    _make_vuln_count_property('vulnerability_code',
                                          extra_query=extra_query,
                                          use_column_property=False),
               ),
               with_expression(
                   Workspace.active_agents_count,
                   _make_active_agents_count_property(),
               ),
            )
        query = count_vulnerability_severities(query, Workspace, status=status, confirmed=confirmed, all_severities=True)

        try:
            obj = query.one()
        except NoResultFound:
            flask.abort(404, f'Object with name "{object_id}" not found')
        return obj

    def _perform_create(self, data, **kwargs):
        start_date = data.get("start_date", None)
        end_date = data.get("end_date", None)
        if start_date and end_date:
            if start_date > end_date:
                abort(make_response(jsonify(message="Workspace start date can't be greater than the end date"), 400))

        scope = data.pop('scope', [])
        workspace = super()._perform_create(data, **kwargs)
        workspace.set_scope(scope)

        db.session.commit()
        return workspace

    def _update_object(self, obj, data, **kwargs):
        scope = data.pop('scope', [])
        obj.set_scope(scope)
        return super()._update_object(obj, data)

    def _dump(self, obj, route_kwargs, **kwargs):
        # When the object was created or updated it doesn't have the stats
        # loaded so I have to query it again
        if not kwargs.get('many') and obj.vulnerability_total_count is None:
            obj = self._get_object(obj.name)
        return super()._dump(obj, route_kwargs, **kwargs)

    @route('/<workspace_id>/activate/', methods=["PUT"])
    def activate(self, workspace_id):
        """
        ---
        put:
          tags: ["Workspace"]
          description: Activate a workspace
          responses:
            200:
              description: Ok
        tags: ["Workspace"]
        responses:
          200:
            description: Ok
        """
        changed = self._get_object(workspace_id).activate()
        db.session.commit()
        return changed

    @route('/<workspace_id>/deactivate/', methods=["PUT"])
    def deactivate(self, workspace_id):
        """
        ---
        put:
          tags: ["Workspace"]
          description: Deactivate a workspace
          responses:
            200:
              description: Ok
        tags: ["Workspace"]
        responses:
          200:
            description: Ok
        """
        changed = self._get_object(workspace_id).deactivate()
        db.session.commit()
        return changed

    @route('/<workspace_id>/change_readonly/', methods=["PUT"])
    def change_readonly(self, workspace_id):
        """
        ---
        put:
          tags: ["Workspace"]
          description: Change readonly workspace's status
          responses:
            200:
              description: Ok
        tags: ["Workspace"]
        responses:
          200:
            description: Ok
        """
        self._get_object(workspace_id).change_readonly()
        db.session.commit()
        return self._get_object(workspace_id).readonly


WorkspaceView.register(workspace_api)
