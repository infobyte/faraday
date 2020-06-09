# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import flask
import logging

from flask import Blueprint, abort, request
from flask_classful import route
from marshmallow import fields, Schema, EXCLUDE
from sqlalchemy.orm.exc import NoResultFound


from faraday.server.api.base import (AutoSchema, UpdateWorkspacedMixin, DeleteWorkspacedMixin,
                                     CountWorkspacedMixin, ReadOnlyWorkspacedView, CreateWorkspacedMixin,
                                     GenericWorkspacedView)
from faraday.server.models import Agent, Executor, AgentExecution, db
from faraday.server.schemas import PrimaryKeyRelatedField
from faraday.server.config import faraday_server
from faraday.server.events import changes_queue

agent_api = Blueprint('agent_api', __name__)

logger = logging.getLogger(__name__)

class ExecutorSchema(AutoSchema):

    parameters_metadata = fields.Dict(
        dump_only=True
    )
    id = fields.Integer(dump_only=True)
    name = fields.String(dump_only=True)

    class Meta:
        model = Executor
        fields = (
            'id',
            'name',
            'parameters_metadata',
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

    class Meta:
        model = Agent
        fields = (
            'id',
            'name',
            'status',
            'active',
            'create_date',
            'update_date',
            'creator',
            'token',
            'is_online',
            'active',
            'executors'
        )


class AgentCreationSchema(Schema):
    id = fields.Integer(dump_only=True)
    token = fields.String(dump_only=False, required=True)
    name = fields.String(required=True)


class AgentCreationView(GenericWorkspacedView, CreateWorkspacedMixin):
    """
    ---
      tags: ["Agent"]
      description: Creates an agent
      responses:
        201:
          description: Ok
          content:
            application/json:
              schema: AgentCreationSchema
        401:
            description: Invalid token
    """
    route_base = 'agent_registration'
    model_class = Agent
    schema_class = AgentCreationSchema

    def _perform_create(self,  data, **kwargs):
        token = data.pop('token')
        if not faraday_server.agent_token:
            # someone is trying to use the token, but no token was generated yet.
            abort(401, "Invalid Token")
        if token != faraday_server.agent_token:
            abort(401, "Invalid Token")

        agent = super(AgentCreationView, self)._perform_create(data, **kwargs)

        return agent


class ExecutorDataSchema(Schema):
    executor = fields.String(default=None)
    args = fields.Dict(default=None)


class AgentRunSchema(Schema):
    executorData = fields.Nested(
        ExecutorDataSchema(unknown=EXCLUDE),
        required=True
    )


class AgentView(UpdateWorkspacedMixin,
                DeleteWorkspacedMixin,
                CountWorkspacedMixin,
                ReadOnlyWorkspacedView):
    route_base = 'agents'
    model_class = Agent
    schema_class = AgentSchema
    get_joinedloads = [Agent.creator, Agent.executors]

    @route('/<int:agent_id>/run/', methods=['POST'])
    def run_agent(self, workspace_name, agent_id):
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
        data = self._parse_data(AgentRunSchema(unknown=EXCLUDE), request)
        agent = self._get_object(agent_id, workspace_name)
        executor_data = data['executorData']

        try:
            executor = Executor.query.filter(Executor.name == executor_data['executor'],
                                         Executor.agent_id == agent_id).one()

            agent_execution = AgentExecution(
                running=None,
                successful=None,
                message='',
                executor=executor,
                workspace_id=executor.agent.workspace_id,
                parameters_data=executor_data["args"]
            )
            db.session.add(agent_execution)
            db.session.commit()

            changes_queue.put({
                'execution_id': agent_execution.id,
                'agent_id': agent.id,
                'action': 'RUN',
                "executor": executor_data.get('executor'),
                "args": executor_data.get('args')
            })
        except NoResultFound as e:
            logger.exception(e)
            abort(400, "Can not find an agent execution with that id")

        return flask.jsonify({
            'successful': True,
        })


AgentView.register(agent_api)
AgentCreationView.register(agent_api)
