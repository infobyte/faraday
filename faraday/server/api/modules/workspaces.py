"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import re
import json
import logging
from datetime import timedelta, date
from itertools import groupby

# Related third party imports
import flask
from flask import Blueprint, abort, make_response, jsonify
from flask_classful import route
from marshmallow import Schema, fields, post_load, ValidationError
from sqlalchemy.orm import with_expression
from sqlalchemy.orm.exc import NoResultFound

# Local application imports
from faraday.server.models import (
    db,
    Workspace,
    SeveritiesHistogram,
    Vulnerability,
    _make_vuln_count_property,
    count_vulnerability_severities,
    _last_run_agent_date,
    _make_generic_count_property,
)
from faraday.server.schemas import (
    JSTimestampField,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from faraday.server.api.base import (
    ReadWriteView,
    AutoSchema,
    FilterMixin,
    BulkDeleteMixin,
    PaginatedMixin,
)

logger = logging.getLogger(__name__)
workspace_api = Blueprint('workspace_api', __name__)


class WorkspaceSummarySchema(Schema):
    credentials = fields.Integer(dump_only=True, attribute='credential_count')
    hosts = fields.Integer(dump_only=True, attribute='host_count')
    services = fields.Integer(dump_only=True, attribute='total_service_count')
    web_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_web_count')
    code_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_code_count')
    std_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_standard_count')
    opened_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_open_count')
    re_opened_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_re_opened_count')
    risk_accepted_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_risk_accepted_count')
    closed_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_closed_count')
    confirmed_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_confirmed_count')
    critical_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_critical_count')
    info_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_informational_count')
    high_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_high_count')
    medium_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_medium_count')
    low_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_low_count')
    unclassified_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_unclassified_count')
    total_vulns = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_total_count')


class HistogramSchema(Schema):
    date = fields.String(dump_only=True, attribute='date')
    medium = fields.Integer(dump_only=True, attribute='medium')
    high = fields.Integer(dump_only=True, attribute='high')
    critical = fields.Integer(dump_only=True, attribute='critical')
    confirmed = fields.Integer(dump_only=True, attribute='confirmed')


class WorkspaceDurationSchema(Schema):
    start_date = JSTimestampField(attribute='start_date')
    end_date = JSTimestampField(attribute='end_date')


def validate_workspace_name(name):
    blacklist = ["filter"]
    if name in blacklist:
        raise ValidationError(f"Not possible to create workspace of name: {name}")
    if not re.match(r"^[A-z0-9][A-z0-9_$()+-]{0,250}$", name):
        raise ValidationError("The workspace name must validate with the regex "
                              "^[a-z0-9][a-z0-9_$()+-]{0,250}$")


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
    importance = fields.Integer(default=0, validate=lambda stars: stars in [0, 1, 2, 3])

    create_date = fields.DateTime(attribute='create_date', dump_only=True)
    update_date = fields.DateTime(attribute='update_date', dump_only=True)
    last_run_agent_date = fields.DateTime(dump_only=True, attribute='last_run_agent_date')
    histogram = fields.Nested(HistogramSchema(many=True))

    class Meta:
        model = Workspace
        fields = ('_id', 'id', 'customer', 'description', 'active',
                  'duration', 'name', 'public', 'scope', 'stats',
                  'create_date', 'update_date', 'readonly',
                  'last_run_agent_date', 'histogram',
                  'importance')

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


def init_date_range(days):
    from_day = date.today()
    date_list = [{'date': (from_day - timedelta(days=x)).strftime("%Y-%m-%d"),
                  Vulnerability.SEVERITY_MEDIUM: 0,
                  Vulnerability.SEVERITY_HIGH: 0,
                  Vulnerability.SEVERITY_CRITICAL: 0,
                  'confirmed': 0} for x in range(days)]
    return date_list


def generate_histogram(days_before):
    histogram_dict = {}

    workspaces_histograms = SeveritiesHistogram.query \
        .order_by(SeveritiesHistogram.workspace_id.asc(), SeveritiesHistogram.date.asc()).all()

    # group dates by workspace
    grouped_histograms_by_ws = groupby(workspaces_histograms, lambda x: x.workspace.name)

    ws_histogram = {}
    for ws_name, dates in grouped_histograms_by_ws:
        first_date = None
        ws_histogram[ws_name] = {}
        # Convert to dict
        for d in dates:
            if first_date is None:
                first_date = d.date
            ws_histogram[ws_name][d.date.strftime("%Y-%m-%d")] = {Vulnerability.SEVERITY_MEDIUM: d.medium,
                                                                  Vulnerability.SEVERITY_HIGH: d.high,
                                                                  Vulnerability.SEVERITY_CRITICAL: d.critical,
                                                                  'confirmed': d.confirmed}

        # fix histogram gaps
        if (date.today() - first_date).days < days_before:
            # move first_date to diff between first day and days required
            first_date = first_date - timedelta(days=(days_before - (date.today() - first_date).days))
        histogram_dict[ws_name] = [{'date': (first_date + timedelta(days=x)).strftime("%Y-%m-%d"),
                                    Vulnerability.SEVERITY_MEDIUM: 0,
                                    Vulnerability.SEVERITY_HIGH: 0,
                                    Vulnerability.SEVERITY_CRITICAL: 0,
                                    'confirmed': 0}
                                   for x in range((date.today() - first_date).days + 1)]

        # merge counters with days required
        confirmed = high = medium = critical = 0
        for current_workspace_histogram_counters in histogram_dict[ws_name]:
            current_date = current_workspace_histogram_counters['date']
            if current_date in ws_histogram[ws_name]:
                medium += ws_histogram[ws_name][current_date][Vulnerability.SEVERITY_MEDIUM]
                high += ws_histogram[ws_name][current_date][Vulnerability.SEVERITY_HIGH]
                critical += ws_histogram[ws_name][current_date][Vulnerability.SEVERITY_CRITICAL]
                confirmed += ws_histogram[ws_name][current_date]['confirmed']
            current_workspace_histogram_counters[Vulnerability.SEVERITY_MEDIUM] = medium
            current_workspace_histogram_counters[Vulnerability.SEVERITY_HIGH] = high
            current_workspace_histogram_counters[Vulnerability.SEVERITY_CRITICAL] = critical
            current_workspace_histogram_counters['confirmed'] = confirmed
        histogram_dict[ws_name] = histogram_dict[ws_name][-days_before:]

    return histogram_dict


def request_histogram():
    histogram_days = flask.request.args.get('histogram_days',
                                            type=lambda x: int(x)
                                            if x.isnumeric() and int(x) > 0
                                            else SeveritiesHistogram.DEFAULT_DAYS_BEFORE,
                                            default=SeveritiesHistogram.DEFAULT_DAYS_BEFORE
                                            )
    histogram_dict = generate_histogram(histogram_days)
    return histogram_days, histogram_dict


class WorkspaceView(ReadWriteView, FilterMixin, BulkDeleteMixin, PaginatedMixin):
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
        histogram = flask.request.args.get('histogram', type=lambda v: v.lower() == 'true')
        histogram_days, histogram_dict = None, None
        if histogram:
            histogram_days, histogram_dict = request_histogram()

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

            if histogram_dict:
                if workspace_stat_dict['name'] in histogram_dict:
                    workspace_stat_dict['histogram'] = histogram_dict[workspace_stat_dict['name']]
                else:
                    workspace_stat_dict['histogram'] = init_date_range(histogram_days)

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
        exclude = []
        stats = True
        histogram = flask.request.args.get('histogram', type=lambda v: v.lower() == 'true')
        exclude_stats = flask.request.args.get('exclude_stats', type=lambda v: v.lower() == 'true')
        if exclude_stats:
            exclude = ['stats']
            stats = False

        histogram_days, histogram_dict = None, None
        if histogram:
            histogram_days, histogram_dict = request_histogram()
        filters = flask.request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters, severity_count=stats, host_vulns=False,
                                            exclude=exclude)
        objects = []

        for workspace_stat in filtered_objs:
            workspace_stat_dict = dict(workspace_stat)
            for key, _ in list(workspace_stat_dict.items()):
                if key.startswith('workspace_'):
                    new_key = key.replace('workspace_', '')
                    workspace_stat_dict[new_key] = workspace_stat_dict[key]
            workspace_stat_dict['scope'] = []

            if histogram_dict:
                if workspace_stat_dict['name'] in histogram_dict:
                    workspace_stat_dict['histogram'] = histogram_dict[workspace_stat_dict['name']]
                else:
                    workspace_stat_dict['histogram'] = init_date_range(histogram_days)

            objects.append(workspace_stat_dict)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(objects, pagination_metadata)

    def _envelope_list(self, objects, pagination_metadata=None):
        return {
            'rows': objects,
            'count': (pagination_metadata.total
                      if pagination_metadata is not None else len(objects))
        }

    def _add_to_filter(self, filter_query, **kwargs):
        filter_query = filter_query.options(
            with_expression(
                Workspace.last_run_agent_date,
                _last_run_agent_date(),
            ),
        )
        return filter_query

    @staticmethod
    def _get_querystring_boolean_field(field_name, default=None):
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

    def _get_object(self, object_id, workspace_name=None, eagerload=False, **kwargs):
        """
        Given the object_id and extra route params, get an instance of
        ``self.model_class``
        """
        obj = None
        confirmed = self._get_querystring_boolean_field('confirmed')
        only_opened = self._get_querystring_boolean_field('only_opened')

        extra_query = ""
        if only_opened:
            extra_query = "status!='closed'"

        self._validate_object_id(object_id)
        query = db.session.query(Workspace).filter_by(name=object_id)

        # Vulnerability Types
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
                Workspace.vulnerability_code_count,
                _make_vuln_count_property('vulnerability_code',
                                          confirmed=confirmed,
                                          extra_query=extra_query,
                                          use_column_property=False),
            ),
            with_expression(
                Workspace.vulnerability_total_count,
                _make_vuln_count_property(type_=None,
                                          confirmed=confirmed,
                                          extra_query=extra_query,
                                          use_column_property=False)
            ),
        )

        # Vulnerability by status
        if not only_opened:
            query = query.options(
                with_expression(Workspace.vulnerability_closed_count,
                                _make_vuln_count_property(None,
                                                          confirmed=confirmed,
                                                          extra_query=" status='closed' ",
                                                          use_column_property=False),
                                )
            )

        query = query.options(
            with_expression(Workspace.vulnerability_open_count,
                            _make_vuln_count_property(None,
                                                      confirmed=confirmed,
                                                      extra_query=" status='open' ",
                                                      use_column_property=False),
                            ),
            with_expression(Workspace.vulnerability_re_opened_count,
                            _make_vuln_count_property(None,
                                                      confirmed=confirmed,
                                                      extra_query=" status='re-opened' ",
                                                      use_column_property=False),
                            ),
            with_expression(Workspace.vulnerability_risk_accepted_count,
                            _make_vuln_count_property(None,
                                                      confirmed=confirmed,
                                                      extra_query=" status='risk-accepted' ",
                                                      use_column_property=False),
                            ),
        )

        # Vulnerabilities by severities
        query = count_vulnerability_severities(query,
                                               Workspace,
                                               confirmed=confirmed,
                                               all_severities=True,
                                               only_opened=only_opened)
        query = query.options(
            with_expression(
                Workspace.credential_count,
                _make_generic_count_property('workspace', 'credential', use_column_property=False)
            ),
            with_expression(
                Workspace.host_count,
                _make_generic_count_property('workspace', 'host', use_column_property=False)
            ),
            with_expression(
                Workspace.total_service_count,
                _make_generic_count_property('workspace', 'service', use_column_property=False)
            ),
        )
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
        logger.info(f"Workspace {workspace_id} activated")
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
        logger.info(f"Workspace {workspace_id} deactivated")
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
        logger.info(f"Change workspace {workspace_id} to readonly")
        return self._get_object(workspace_id).readonly

    def _bulk_delete_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        return self.model_class.query.filter(self.model_class.name.in_(ids))


WorkspaceView.register(workspace_api)
