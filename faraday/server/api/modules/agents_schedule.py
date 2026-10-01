"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import http
import logging
from datetime import datetime
from uuid import uuid4

# Related third party imports
import flask
from flask import (
    Blueprint,
    abort,
)
import flask_login
from flask_classful import route
from marshmallow import fields, post_load
from sqlalchemy.orm.exc import NoResultFound

# Local application imports
from faraday.server.api.base import InvalidUsage
from faraday.server.api.modules.agent import AgentSchema, ExecutorSchema
from faraday.server.api.modules.scheduler import SchedulerView, SchedulerSchema
from faraday.server.extensions import socketio
from faraday.server.models import (
    Agent,
    AgentsSchedule,
    Executor,
    db,
)
from faraday.server.utils.agents import get_command_and_agent_execution

agents_schedule_api = Blueprint('agents_schedule_api', __name__)
logger = logging.getLogger(__name__)


class AgentsScheduleSchema(SchedulerSchema):
    executor = fields.Nested(ExecutorSchema(), dump_only=True)
    agent = fields.Method('get_agent', dump_only=True)

    class Meta(SchedulerSchema.Meta):
        model = AgentsSchedule
        fields = SchedulerSchema.Meta.fields + (
            'executor',
            'agent',
        )

    @post_load
    def post_load_executor(self, data, **kwargs):
        if 'executor_id' in data:
            executor_id = data.pop('executor_id')
            try:
                executor = db.session.query(Executor).filter_by(id=executor_id).one()
                data['executor'] = executor
            except NoResultFound as e:
                raise InvalidUsage(f'Executor id not found: {executor_id}') from e
        return data

    @staticmethod
    def get_agent(obj):
        agent_id = obj.executor.agent_id
        try:
            agent = db.session.query(Agent). \
                filter(Agent.id == agent_id).one()
        except NoResultFound as e:
            raise InvalidUsage(f'Agent id not found: {agent_id}') from e
        ret = AgentSchema().dump(agent)
        return ret


class AgentsScheduleView(SchedulerView):
    route_base = 'agents_schedule'
    model_class = AgentsSchedule
    order_field = AgentsSchedule.id.asc()
    schema_class = AgentsScheduleSchema

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
            message = f"Schedule with ID {schedule_id} not found!, skipping agent execution"
            logger.warning(message)
            flask.abort(400, message)
        agent = agents_schedule.executor.agent
        if agents_schedule.executor.agent.is_offline:
            message = 'Agent is offline'
            abort(http.HTTPStatus.GONE, message)
        if not agents_schedule.executor.agent.active:
            message = f'Agent is paused. active flag: {agents_schedule.executor.agent.active}'
            abort(http.HTTPStatus.GONE, message)
        plugin_args = {
            "ignore_info": agents_schedule.ignore_info,
            "resolve_hostname": agents_schedule.resolve_hostname,
            "min_severity": agents_schedule.min_severity,
            "max_severity": agents_schedule.max_severity,
        }
        if agents_schedule.vuln_tag:
            plugin_args["vuln_tag"] = agents_schedule.vuln_tag.split(",")
        if agents_schedule.service_tag:
            plugin_args["service_tag"] = agents_schedule.service_tag.split(",")
        if agents_schedule.host_tag:
            # this field should be named host_tag but in agents is named as hostname_tag
            plugin_args["hostname_tag"] = agents_schedule.host_tag.split(",")

        workspaces = agents_schedule.workspaces
        commands = []
        agent_executions = []
        workspaces_commands = []
        parameters_data = {
            "executor_data": {"args": agents_schedule.parameters},
            "workspaces_commands": []
        }
        run_uuid = uuid4()
        for workspace in workspaces:
            command, agent_execution = get_command_and_agent_execution(
                executor=agents_schedule.executor,
                workspace=workspace,
                parameters=parameters_data,
                username=username,
                user_id=flask_login.current_user.id,
                run_uuid=run_uuid
            )
            commands.append(command)
            db.session.add(command)
            db.session.commit()
            agent_executions.append(agent_execution)
            workspaces_commands.append({"workspace_name": workspace.name, "command_id": command.id})

        parameters_data["workspaces_commands"] = workspaces_commands
        parameters_data.update(**plugin_args)

        for agent_execution in agent_executions:
            agent_execution.parameters_data = parameters_data
            db.session.add(agent_execution)
        agents_schedule.last_run = datetime.utcnow()
        db.session.commit()

        message = {
            "execution_ids": [ae.id for ae in agent_executions],
            "agent_id": agent.id,
            "workspaces": [ws.name for ws in workspaces],
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
