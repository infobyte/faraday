"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import http
import json
import logging
from datetime import datetime
from uuid import uuid4

import pyotp
import flask
from flask import Blueprint, abort, request, jsonify
import flask_login
from flask_classful import route
from marshmallow import fields, Schema, EXCLUDE
from marshmallow.validate import OneOf
from sqlalchemy import and_, exists, func, or_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm.exc import NoResultFound
from faraday_agent_parameters_types.utils import type_validate, get_manifests
from faraday.server.utils.search import OPERATORS

from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView,
    FilterMixin,
    BulkDeleteMixin,
    get_workspace
)
from faraday.server.extensions import socketio
from faraday.server.models import (
    Agent,
    Executor,
    SchedulerGeneric,
    db,
)
from faraday.server.schemas import PrimaryKeyRelatedField
from faraday.server.config import faraday_server
from faraday.server.utils.agents import get_command_and_agent_execution

agent_api = Blueprint('agent_api', __name__)
agent_creation_api = Blueprint('agent_creation_api', __name__)
logger = logging.getLogger(__name__)


def validate_type(base, type_, value):
    """Validate a value based on its base and type."""

    type_mapping = {
        "string": str,
        "integer": int,
        "boolean": bool,
        "list": list
    }

    expected_type = type_mapping.get(base)
    if expected_type is None:
        return f"Unknown base type: {base}"

    if not isinstance(value, expected_type):
        return f"Expected {base}, got {type(value).__name__}"

    return None  # No error, value is valid


def validate_executor_args(parameters_metadata, args):
    """Validate executor arguments based on parameters metadata."""
    errors = {}

    # Iterate through the passed arguments (args)
    for param_name, param_value in args.items():
        # If this param exists in the metadata, validate it
        if param_name in parameters_metadata:
            param_metadata = parameters_metadata[param_name]
            error = validate_type(param_metadata["base"], param_metadata["type"], param_value)
            if error:
                errors[param_name] = error

    return errors


class ExecutorScheduleStubSchema(AutoSchema):
    id = fields.Integer(dump_only=True)
    description = fields.String(required=True)


class ExecutorSchema(AutoSchema):

    parameters_metadata = fields.Dict(
        dump_only=True
    )
    parameters_data = fields.Dict(
        dump_only=True
    )
    id = fields.Integer(dump_only=True)
    name = fields.String(dump_only=True)
    agent_id = fields.Integer(dump_only=True, attribute='agent_id')
    last_run = fields.DateTime(dump_only=True)
    schedules = fields.Nested(ExecutorScheduleStubSchema(), dump_only=True, many=True)
    tool = fields.String(dump_only=True)
    category = fields.List(fields.String(), dump_only=True)

    class Meta:
        model = Executor
        fields = (
            'id',
            'name',
            'agent_id',
            'last_run',
            'parameters_metadata',
            'parameters_data',
            'schedules',
            'tool',
            'category',
        )


class AgentSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    status = fields.String(dump_only=True)
    creator = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    token = fields.String(dump_only=True)
    create_date = fields.DateTime(dump_only=True)
    update_date = fields.DateTime(dump_only=True)
    is_online = fields.Boolean(dump_only=True)
    executors = fields.Nested(ExecutorSchema(), dump_only=True, many=True)
    last_run = fields.DateTime(dump_only=True)
    description = fields.String(dump_only=True)

    class Meta:
        model = Agent
        fields = (
            'id',
            'name',
            'description',
            'status',
            'active',
            'create_date',
            'update_date',
            'creator',
            'is_online',
            'active',
            'executors',
            'last_run'
        )


class AgentCreationSchema(Schema):
    id = fields.Integer(dump_only=True)
    token = fields.String(dump_only=False, required=True)
    name = fields.String(required=True)
    description = fields.String(required=False)

    class Meta:
        fields = (
            'id',
            'name',
            'token',
            'description',
        )


class ExecutorDataSchema(Schema):
    executor = fields.String(default=None)
    args = fields.Dict(default=None)


class AgentRunSchema(Schema):
    executor_data = fields.Nested(
        ExecutorDataSchema(unknown=EXCLUDE),
        required=True
    )
    workspaces_names = fields.List(fields.String, required=True)
    ignore_info = fields.Boolean(required=False)
    resolve_hostname = fields.Boolean(required=False)
    vuln_tag = fields.List(fields.String, required=False)
    service_tag = fields.List(fields.String, required=False)
    host_tag = fields.List(fields.String, required=False)
    min_severity = fields.String(required=False, allow_none=True,
                                 validate=OneOf(SchedulerGeneric.SEVERITIES))
    max_severity = fields.String(required=False, allow_none=True,
                                 validate=OneOf(SchedulerGeneric.SEVERITIES))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unknown = EXCLUDE


# Filters that require custom SQLAlchemy — cannot be expressed with standard OPERATORS
_AGENT_CUSTOM_FILTER_NAMES = frozenset({'last_execution_date', 'last_execution_tool', 'category'})

# Binary comparison operators valid for scalar subquery filters (last_execution_date).
# 1-arg (is_null, is_not_null) and ordering (asc, desc) ops take a wrong arity → TypeError.
_DATE_COMPARISON_OPS = frozenset({'eq', '==', 'ne', '!=', 'neq', 'lt', '<', 'le', '<=', 'gt', '>', 'ge', '>='})


def _build_agent_conditions(custom_filters):
    conditions = []
    for f in custom_filters:
        name = f.get('name')
        op = str(f.get('op') or 'eq').lower()
        val = f.get('val', '')

        if name == 'last_execution_date':
            if op not in _DATE_COMPARISON_OPS:
                abort(400, f"Unsupported operator {op!r} for last_execution_date; use eq/ne/lt/le/gt/ge")
            if not isinstance(val, str):
                abort(400, f"Invalid date format for last_execution_date: {val!r}")
            try:
                dval = datetime.fromisoformat(val.replace('Z', '+00:00'))
            except ValueError:
                abort(400, f"Invalid date format for last_execution_date: {val!r}")
            max_lr = (
                db.session.query(func.max(Executor.last_run))
                .filter(Executor.agent_id == Agent.id)
                .correlate(Agent)
                .as_scalar()
            )
            if 'T' in val:
                conditions.append(OPERATORS[op](max_lr, dval))
            else:
                conditions.append(OPERATORS[op](func.date(max_lr), dval.date()))

        elif name == 'tools':
            op_lower = op.lower()
            if op_lower in ('is_one_of', 'in'):
                vals = val if isinstance(val, list) else [v.strip() for v in str(val).split(',') if v.strip()]
                conditions.append(
                    exists().where(and_(Executor.agent_id == Agent.id, Executor.tool.in_(vals)))
                )
            elif op_lower in ('is_not_one_of', 'not_in', 'nin'):
                vals = val if isinstance(val, list) else [v.strip() for v in str(val).split(',') if v.strip()]
                conditions.append(
                    ~exists().where(and_(Executor.agent_id == Agent.id, Executor.tool.in_(vals)))
                )
            elif op_lower not in ('contains', 'ilike', 'like'):
                abort(400, f"Unsupported operator {op!r} for tools filter; use 'contains', 'like', 'ilike', 'is_one_of', or 'is_not_one_of'")
            else:
                tool_escaped = str(val).replace('%', r'\%').replace('_', r'\_')
                conditions.append(
                    exists().where(and_(
                        Executor.agent_id == Agent.id,
                        Executor.name.ilike(f'%{tool_escaped}%'),
                    ))
                )

        elif name == 'last_execution_tool':
            tool = str(val)
            op_lower = op.lower()
            max_lr = (
                db.session.query(func.max(Executor.last_run))
                .filter(Executor.agent_id == Agent.id)
                .correlate(Agent)
                .as_scalar()
            )
            if op_lower in ('eq', '=='):
                name_cond = Executor.name == tool
            elif op_lower in ('ne', '!=', 'neq'):
                name_cond = Executor.name != tool
            else:
                tool_escaped = tool.replace('%', r'\%').replace('_', r'\_')
                name_cond = Executor.name.ilike(f'%{tool_escaped}%')
            conditions.append(
                exists().where(and_(Executor.agent_id == Agent.id, Executor.last_run == max_lr, name_cond))
            )

        elif name == 'category':
            vals = val if isinstance(val, list) else [v.strip() for v in str(val).split(',') if v.strip()]
            op_lower = op.lower()
            cats = [
                exists().where(and_(Executor.agent_id == Agent.id, Executor.category.cast(JSONB).contains([v])))
                for v in vals
            ]
            if cats:
                combined = or_(*cats)
                if op_lower in ('is_not_one_of', 'not_in', 'nin', 'ne', '!=', 'neq'):
                    conditions.append(~combined)
                else:
                    conditions.append(combined)

    return conditions


class AgentView(ReadWriteView, FilterMixin, BulkDeleteMixin):
    route_base = 'agents'
    model_class = Agent
    schema_class = AgentSchema
    get_joinedloads = [Agent.creator, Agent.executors]

    def post(self, **kwargs):
        self.schema_class = AgentCreationSchema
        obj, status = super().post(**kwargs)
        self.schema_class = AgentSchema
        return obj, status

    def _perform_create(self, data, **kwargs):
        token = data.pop('token')
        if not faraday_server.agent_registration_secret:
            # someone is trying to use the token, but no token was generated yet.
            abort(401, "Invalid Token")
        if not pyotp.TOTP(faraday_server.agent_registration_secret,
                          interval=int(faraday_server.agent_token_expiration)
                          ).verify(token, valid_window=1):
            abort(401, "Invalid Token")
        agent = super()._perform_create(data, **kwargs)
        return agent

    @route('/<int:agent_id>/run', methods=['POST'])
    def run_agent(self, agent_id):
        """
        ---
          tags: ["Agent"]
          description: Runs an agent
          requestBody:
            required: true
            content:
              application/json:
                schema: AgentRunSchema
          responses:
            400:
              description: Bad request
            201:
              description: Ok
              content:
                application/json:
                  schema: AgentSchema
        """
        if flask.request.content_type != 'application/json':
            abort(400, "Only application/json is a valid content-type")
        user = flask_login.current_user
        data = self._parse_data(AgentRunSchema(unknown=EXCLUDE), request)
        agent = self._get_object(agent_id)
        workspaces = [get_workspace(workspace_name=workspace) for workspace in data['workspaces_names']]
        plugins_args = {
            "ignore_info": data.get('ignore_info', False),
            "resolve_hostname": data.get('resolve_hostname', True),
            "vuln_tag": data.get('vuln_tag', None),
            "service_tag": data.get('service_tag', None),
            # this field should be named host_tag but in agents is named as hostname_tag
            "hostname_tag": data.get('host_tag', None),
            "min_severity": data.get('min_severity', None),
            "max_severity": data.get('max_severity', None)
        }
        if agent.is_offline:
            abort(http.HTTPStatus.GONE, "Agent is offline")
        return self._run_agent(agent, data, workspaces, plugins_args, user.username, user.id)

    @staticmethod
    def _run_agent(agent: Agent, parameters_data: dict, workspaces: list, plugins_args: dict, username: str, user_id: int):
        executor_data = parameters_data["executor_data"]
        try:
            executor = Executor.query.filter(Executor.name == executor_data['executor'],
                                             Executor.agent_id == agent.id).one()

            # VALIDATE
            errors = {}
            for param_name, param_data in executor_data["args"].items():
                if executor.parameters_metadata.get(param_name):
                    val_error = type_validate(executor.parameters_metadata[param_name]['type'], param_data)
                    if val_error:
                        errors[param_name] = val_error
                else:
                    errors['message'] = f'"{param_name}" not recognized as an executor argument'

            for param_name, _ in executor.parameters_metadata.items():
                if executor.parameters_metadata[param_name]['mandatory'] and param_name not in executor_data['args']:
                    errors['message'] = f'Mandatory argument {param_name} not passed to {executor.name} executor.'

            if errors:
                response = jsonify(errors)
                response.status_code = 400
                abort(response)

            commands = []
            agent_executions = []
            workspaces_commands = []
            run_uuid = uuid4()
            for workspace in workspaces:
                command, agent_execution = get_command_and_agent_execution(executor=executor,
                                                                           workspace=workspace,
                                                                           user_id=user_id,
                                                                           parameters=parameters_data,
                                                                           username=username,
                                                                           triggered_by=username,
                                                                           run_uuid=run_uuid)
                commands.append(command)
                db.session.add(command)
                db.session.commit()
                agent_executions.append(agent_execution)
                workspaces_commands.append({"workspace_name": workspace.name, "command_id": command.id})

            parameters_data["workspaces_commands"] = workspaces_commands
            parameters_data.pop("workspaces_names", None)

            executor.last_run = datetime.utcnow()
            for agent_execution in agent_executions:
                agent_execution.parameters_data = parameters_data
                db.session.add(agent_execution)
            db.session.commit()

            message = {
                'execution_ids': [agent_execution.id for agent_execution in agent_executions],
                'agent_id': agent.id,
                'workspaces': [workspace.name for workspace in workspaces],
                'action': 'RUN',
                "executor": executor_data.get('executor'),
                "args": executor_data.get('args'),
                "plugin_args": plugins_args
            }
            if agent.is_online:
                socketio.emit("run", message, to=agent.sid, namespace='/dispatcher')
                logger.info(f"Agent {agent.name} executed with executor {executor.name}")
            else:
                # TODO: set command's end_date
                error = "Agent %s with id %s is offline.", agent.name, agent.id
                logger.warning(error)
                abort(http.HTTPStatus.GONE, error)
        except NoResultFound as e:
            logger.exception(e)
            abort(400, "Can not find an executor with that agent id")
        else:
            return flask.jsonify({
                'commands_id': [command.id for command in commands]
            })

    @route('/active_agents', methods=['GET'])
    def active_agents(self, **kwargs):
        """
        ---
        get:
          tags: ["Agent"]
          summary: Get all manifests, Optionally choose latest version with parameter
          parameters:
          - in: query
            name: agent_version
            description: latest version to request
            schema:
              type: string

          responses:
            200:
              description: Ok
        """
        try:
            objects = self.model_class.query.filter(self.model_class.active).all()
            return self._envelope_list(self._dump(objects, kwargs, many=True))
        except ValueError as e:
            flask.abort(400, e)

    @route('/get_manifests', methods=['GET'])
    def manifests_get(self):
        """
        ---
        get:
          tags: ["Agent"]
          summary: Get all manifests, Optionally choose latest version with parameter
          parameters:
          - in: query
            name: agent_version
            description: latest version to request
            schema:
              type: string

          responses:
            200:
              description: Ok
        """
        try:
            manifest = get_manifests(request.args.get("agent_version")).copy()
            if "BURP_API_PULL_INTERVAL" in manifest.get("burp", {}).get("environment_variables", ""):
                manifest["burp"]["optional_environment_variables"] = [
                    manifest["burp"].get("environment_variables").pop(
                        manifest["burp"]["environment_variables"].index("BURP_API_PULL_INTERVAL")
                    )
                ]
            if "TENABLE_PULL_INTERVAL" in manifest.get("tenableio", {}).get("environment_variables", ""):
                manifest["tenableio"]["optional_environment_variables"] = [
                    manifest["tenableio"]["environment_variables"].pop(
                        manifest["tenableio"]["environment_variables"].index("TENABLE_PULL_INTERVAL")
                    )
                ]
            return flask.jsonify(manifest)
        except ValueError as e:
            flask.abort(400, e)

    @route('/save_parameters', methods=['POST'])
    def save_parameters_data(self):
        """
        ---
        tags: ["Agent"]
        description: Saves parameters data for an executor
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  executor_id:
                    type: integer
                    description: The ID of the executor
                  parameters_data:
                    type: object
                    description: Full parameters data to be saved
        responses:
          200:
            description: Parameters saved successfully
          400:
            description: Validation error
          404:
            description: Executor not found
        """
        if flask.request.content_type != 'application/json':
            abort(400, "Only application/json is a valid content-type")

        data = request.get_json()
        executor_id = data.get("executor_id")
        parameters_data = data.get("parameters_data")

        if not executor_id:
            abort(400, "Missing 'executor_id' in request body")
        if not parameters_data:
            abort(400, "Missing 'parameters_data' in request body")

        executor = Executor.query.get(executor_id)
        if not executor:
            abort(404, "Executor not found")

        executor_data = parameters_data.get("executor_data", {})
        args = executor_data.get("args", {})
        parameters_metadata = executor.parameters_metadata

        validation_errors = validate_executor_args(parameters_metadata, args)

        if validation_errors:
            return jsonify({"errors": validation_errors}), 400

        # Proceed to save the parameters data if validation passes
        executor.parameters_data = parameters_data
        db.session.commit()

        return jsonify({"message": "Parameters saved successfully"}), 200

    def _generate_filter_query(self, filters, severity_count=None):
        if 'group_by' not in filters:
            order_by = filters.get('order_by') or []
            filters['order_by'] = (
                order_by
                + [
                    {'field': 'active', 'direction': 'desc'},
                    {'field': 'sid', 'direction': 'desc'},
                ]
                + [{'field': 'id', 'direction': 'asc'}]
            )
        return super()._generate_filter_query(filters, severity_count=severity_count)

    def _translate_filters(self, filters):
        try:
            raw = json.loads(filters) if isinstance(filters, str) else dict(filters or {})
        except (ValueError, TypeError):
            abort(400, 'Invalid filter JSON')
        top = raw.get('filters', [])
        standard = []
        sql_custom = []
        for f in top:
            if not isinstance(f, dict):
                standard.append(f)
                continue
            name = f.get('name')
            op = str(f.get('op') or 'eq').lower()
            val = f.get('val', '')
            if name == 'status':
                is_online = str(val).lower() == 'online'
                if op in ('ne', '!=', 'neq'):
                    is_online = not is_online
                standard.append({"name": "sid", "op": "is_not_null" if is_online else "is_null", "val": ""})
            elif name == 'blocked':
                is_blocked = str(val).lower() in ('true', '1', 'yes')
                if op in ('ne', '!=', 'neq'):
                    is_blocked = not is_blocked
                standard.append({"name": "active", "op": "eq", "val": not is_blocked})
            elif name in ('name', 'description') and op == 'contains':
                standard.append({"name": name, "op": "ilike", "val": f"%{val}%"})
            elif name == 'tools':
                tool = str(val)
                if op in ('eq', '=='):
                    standard.append({"name": "executors", "op": "any", "val": {"name": "name", "op": "eq", "val": tool}})
                elif op in ('ne', '!=', 'neq'):
                    standard.append({"name": "executors", "op": "not_any", "val": {"name": "name", "op": "eq", "val": tool}})
                else:
                    sql_custom.append(f)
            elif name in _AGENT_CUSTOM_FILTER_NAMES:
                sql_custom.append(f)
            else:
                standard.append(f)
        conditions = _build_agent_conditions(sql_custom)
        extra = and_(*conditions) if conditions else None
        raw['filters'] = standard
        return json.dumps(raw), extra

    def _filter(self, filters, extra_alchemy_filters=None, **kwargs):
        translated, extra = self._translate_filters(filters)
        if extra is not None and extra_alchemy_filters is not None:
            extra = and_(extra_alchemy_filters, extra)
        elif extra_alchemy_filters is not None:
            extra = extra_alchemy_filters
        return super()._filter(translated, extra_alchemy_filters=extra, **kwargs)

    @route('/filter')
    def filter(self, **kwargs):
        """
        ---
        tags: ["Filter", "Agent"]
        description: Filters, sorts and groups Agents using a json with parameters. These parameters must be part of the model.
        parameters:
        - in: query
          name: q
          description: Recursive json with filters that supports operators. The json could also contain sort and group.
          schema:
            type: string
        responses:
          200:
            description: Returns filtered, sorted and grouped results
            content:
              application/json:
                schema: FlaskRestlessSchema
          400:
            description: Invalid q was sent to the server
        """
        filters = request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters, **kwargs)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count

        return {
            'rows': filtered_objs,
            'count': pagination_metadata.total if pagination_metadata else len(filtered_objs)
        }


AgentView.register(agent_api)
