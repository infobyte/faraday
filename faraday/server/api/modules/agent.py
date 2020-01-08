# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import json

import flask
import wtforms

from flask import Blueprint, abort, request
from flask_classful import route
from flask_wtf.csrf import validate_csrf
from marshmallow import fields, Schema

from faraday.server.api.base import (AutoSchema, UpdateWorkspacedMixin, DeleteWorkspacedMixin,
                                     CountWorkspacedMixin, ReadOnlyWorkspacedView, CreateWorkspacedMixin,
                                     GenericWorkspacedView)
from faraday.server.models import Agent, Executor
from faraday.server.schemas import PrimaryKeyRelatedField, MutableField, SelfNestedField
from faraday.server.config import faraday_server
from faraday.server.events import changes_queue

agent_api = Blueprint('agent_api', __name__)


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
    executorData = fields.Nested(ExecutorDataSchema(), required=True)


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
        if flask.request.content_type != 'application/json':
            abort(400, "Only application/json is a valid content-type")
        data = self._parse_data(AgentRunSchema(strict=True), request)
        agent = self._get_object(agent_id, workspace_name)
        executor_data = data['executorData']
        changes_queue.put({
            'agent_id': agent.id,
            'action': 'RUN',
            "executor": executor_data.get('executor'),
            "args": executor_data.get('args')
        })
        return flask.jsonify({
            'successful': True,
        })


AgentView.register(agent_api)
AgentCreationView.register(agent_api)
