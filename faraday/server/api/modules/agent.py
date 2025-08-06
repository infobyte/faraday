"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import http
import logging
from datetime import datetime
from uuid import uuid4

import pyotp
import flask
from flask import Blueprint, abort, request, jsonify
import flask_login
from flask_classful import route
from marshmallow import fields, Schema, EXCLUDE
from sqlalchemy.orm.exc import NoResultFound
from faraday_agent_parameters_types.utils import type_validate, get_manifests

from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView,
    FilterMixin,
    get_workspace
)
from faraday.server.extensions import socketio
from faraday.server.models import (
    Agent,
    Executor,
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


class AgentsScheduleSchema(AutoSchema):
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
    schedules = fields.Nested(AgentsScheduleSchema(), dump_only=True, many=True)
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
            'description'
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
    # TODO: add validation for severity fields
    min_severity = fields.String(required=False, allow_none=True)
    max_severity = fields.String(required=False, allow_none=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unknown = EXCLUDE


class AgentView(ReadWriteView, FilterMixin):
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
          - in: version
            name: agent_version
            description: latest version to request

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
          - in: version
            name: agent_version
            description: latest version to request

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
