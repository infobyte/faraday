"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import http
import logging
import json
import datetime

# Related third party imports
import flask
from flask import (
    Blueprint,
    abort,
)
import flask_login
from flask_classful import route
from marshmallow import (
    fields,
    pre_dump,
    post_load,
    validate,
    ValidationError
)
from sqlalchemy.orm.exc import NoResultFound
import dateutil

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    InvalidUsage,
    PaginatedMixin,
    ReadWriteView,
    get_workspace
)
from faraday.server.api.modules.agent import AgentSchema, ExecutorSchema
from faraday.server.api.modules.workspaces import WorkspaceSchema
from faraday.server.extensions import socketio
from faraday.server.schemas import (
    PrimaryKeyRelatedField,
    SelfNestedField,
    MetadataSchema,
)
from faraday.server.utils.agents import get_command_and_agent_execution
from faraday.server.models import (
    Agent,
    AgentsSchedule,
    db,
    Executor,
)
agents_schedule_api = Blueprint('agents_schedule_api', __name__)
logger = logging.getLogger(__name__)

SCHEDULES_LIMIT = 2


def check_timezone(tz: str):
    if not dateutil.tz.gettz(tz):
        raise ValidationError("Invalid timezone")


class AgentsScheduleSchema(AutoSchema):
    id = fields.Integer(dump_only=True)
    description = fields.String(required=True)
    crontab = fields.String(required=True,
                            validate=validate
                            .Regexp
                            (r"^(((([1-5]?\d(-([1-5]?\d))?|\*)(\/(\d+))?),?)+)\ (((((2[0-3]|1?\d)(-(2["
                             r"0-3]|1?\d))?|\*)(\/(\d+))?),?)+)\ (((((3[01]|[12]?\d)(-(3[01]|[12]?\d))?|\*)(\/("
                             r"\d+))?),?)+)\ (((((1[0-2]|\d)(-(1[0-2]|\d))?|\*)(\/(\d+))?),?)+)\ (((([0-6](-(["
                             r"0-6]))?|\*)(\/(\d+))?),?)+)$",
                             0,
                             error='Invalid format, Please use basic crontab format, Example: 10 * 10 * *'))
    timezone = fields.String(required=True,
                             validate=check_timezone
                             )
    active = fields.Boolean(default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True,
                                   attribute='owner')
    executor_id = fields.Integer(dump_only=False)
    executor = fields.Nested(ExecutorSchema(), dump_only=True)
    agent = fields.Method('get_agent', dump_only=True)
    next_run = fields.String(dump_only=True)
    parameters = fields.Method(deserialize='load_parameters', serialize='send_parameters')
    metadata = SelfNestedField(MetadataSchema())
    workspaces_names = fields.List(fields.String, required=True)
    workspaces = fields.List(fields.Pluck(WorkspaceSchema, 'name'))
    ignore_info = fields.Boolean(required=False, default=False)
    resolve_hostname = fields.Boolean(required=False, default=True)
    vuln_tag = fields.List(fields.String, required=False)
    service_tag = fields.List(fields.String, required=False)
    host_tag = fields.List(fields.String, required=False)

    class Meta:
        model = AgentsSchedule
        fields = (
            'id',
            'description',
            'crontab',
            'timezone',
            'active',
            'owner',
            'executor_id',
            'executor',
            'agent',
            'parameters',
            'next_run',
            'metadata',
            'workspaces_names',
            'workspaces',
            "ignore_info",
            "resolve_hostname",
            "vuln_tag",
            "service_tag",
            "host_tag"
        )

    @staticmethod
    def load_parameters(value):
        return json.loads(value)

    @staticmethod
    def send_parameters(value):
        return value.parameters

    @post_load
    def post_load_executor(self, data, **kwargs):
        if 'partial' not in kwargs or not kwargs['partial']:
            if 'executor_id' in data:
                executor_id = data.pop('executor_id')
                try:
                    executor = db.session.query(Executor).filter(Executor.id == executor_id).one()
                except NoResultFound as e:
                    raise InvalidUsage(f'Executor id not found: {executor_id}') from e
                data['executor'] = executor
        if "workspaces_names" in data:
            workspaces = [get_workspace(workspace_name=workspace_name) for workspace_name
                          in data.pop("workspaces_names")]
            data['workspaces'] = workspaces
        if "vuln_tag" in data:
            data['vuln_tag'] = ",".join(data['vuln_tag'])
        if "host_tag" in data:
            data['host_tag'] = ",".join(data['host_tag'])
        if "service_tag" in data:
            data['service_tag'] = ",".join(data['service_tag'])
        return data

    @pre_dump
    def pre_dump_executor(self, data, **kwargs):
        if data.vuln_tag:
            data.vuln_tag = data.vuln_tag.split(',')
        if data.host_tag:
            data.host_tag = data.host_tag.split(',')
        if data.service_tag:
            data.service_tag = data.service_tag.split(',')
        return data

    @staticmethod
    def get_agent(obj):
        agent_id = obj.executor.agent_id
        try:
            agent = db.session.query(Agent).\
                filter(Agent.id == agent_id).one()
        except NoResultFound as e:
            raise InvalidUsage(f'Agent id not found: {agent_id}') from e
        ret = AgentSchema().dump(agent)
        return ret


class AgentsScheduleView(
        PaginatedMixin,
        ReadWriteView):
    route_base = 'agents_schedule'
    model_class = AgentsSchedule
    order_field = AgentsSchedule.id.asc()
    schema_class = AgentsScheduleSchema

    def _envelope_list(self, objects, pagination_metadata=None):
        agents_schedule = []
        objects = objects if objects is not None else []
        for schedule in objects:
            agents_schedule.append({
                'id': schedule['id'],
                'key': schedule['id'],
                'value': schedule
            })
        return {
            'rows': agents_schedule,
            'total_rows': (pagination_metadata and pagination_metadata.total
                           or len(agents_schedule)),
        }

    def _perform_create(self, data):
        schedules_in_use = db.session.query(AgentsSchedule).count()
        schedules_limit = SCHEDULES_LIMIT
        if schedules_in_use >= schedules_limit:
            message = "Agent schedules limit reached. Can't create new Schedules"
            logger.error(message)
            return flask.abort(403, message)

        created = super()._perform_create(data)
        schedule_message = f"Schedule created [Workspaces: {data['workspaces']} - description: {data['description']} " \
                           f"- executor: {data['executor']} - crontab: {data['crontab']}]"
        logger.info(schedule_message)
        return created

    @route('/<int:schedule_id>/run', methods=['POST'])
    def run_schedule(self, schedule_id):
        """
        ---
          tags: ["Agent Schedule"]
          description: Runs an agent schedule
          responses:
            400:
              description: Bad request
            201:
              description: Ok
        """
        username = flask_login.current_user.username
        agents_schedule = self._get_object(schedule_id)
        if not agents_schedule:
            message = f"Schedule with ID {self.schedule_id} not found!, skipping agent execution"
            logger.warning(message)
            flask.abort(400, message)
        if agents_schedule.executor.agent.is_offline:
            message = 'Agent is offline'
            abort(http.HTTPStatus.GONE, message)
        if not agents_schedule.executor.agent.active:
            message = f'Agent is paused. active flag: {agents_schedule.executor.agent.active}'
            abort(http.HTTPStatus.GONE, message)
        agents_schedule.last_run = datetime.datetime.now()
        db.session.add(agents_schedule)
        workspaces = agents_schedule.workspaces
        commands = []
        agent_executions = []
        for workspace in workspaces:
            command, agent_execution = get_command_and_agent_execution(
                executor=agents_schedule.executor,
                workspace=workspace,
                parameters=agents_schedule.parameters,
                username=username,
                user_id=flask_login.current_user.id
            )
            commands.append(command)
            agent_executions.append(agent_execution)
            db.session.add(agent_execution)
        db.session.commit()
        logger.info(f"Agent {agents_schedule.executor.agent.name} executed with executor {agents_schedule.executor.name}")
        plugin_args = {
            "ignore_info": agents_schedule.ignore_info,
            "resolve_hostname": agents_schedule.resolve_hostname
        }
        if agents_schedule.vuln_tag:
            plugin_args["vuln_tag"] = agents_schedule.vuln_tag.split(",")
        if agents_schedule.service_tag:
            plugin_args["service_tag"] = agents_schedule.service_tag.split(",")
        if agents_schedule.host_tag:
            # this field should be named host_tag but in agents is named as hostname_tag
            plugin_args["hostname_tag"] = agents_schedule.host_tag.split(",")
        message = {
            "execution_ids": [agent_execution.id for agent_execution in agent_executions],
            "agent_id": agents_schedule.executor.agent.id,
            "workspaces": [workspace.name for workspace in workspaces],
            "action": 'RUN',
            "executor": agents_schedule.executor.name,
            "args": agents_schedule.parameters,
            "plugin_args": plugin_args
        }
        socketio.emit("run", message, to=agents_schedule.executor.agent.sid, namespace='/dispatcher')
        logger.info(f"Agent {agents_schedule.executor.agent.name} "
                    f"executed with executor {agents_schedule.executor.name}")

        return flask.jsonify({
            'commands_id': [command.id for command in commands],
        })


AgentsScheduleView.register(agents_schedule_api)
