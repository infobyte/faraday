# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from datetime import datetime

import flask
import logging

from flask import Blueprint, abort, request, make_response, jsonify
from flask_classful import route
from marshmallow import fields, Schema, EXCLUDE
from sqlalchemy.orm.exc import NoResultFound


from faraday.server.api.base import (
    AutoSchema,
    UpdateMixin,
    DeleteMixin,
    ReadOnlyView,
    CreateMixin,
    GenericView,
    ReadOnlyMultiWorkspacedView,
    PatchableMixin
)
from faraday.server.api.modules.workspaces import WorkspaceSchema
from faraday.server.models import Agent, Executor, AgentExecution, db, \
    Workspace, Command
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


class AgentWithWorkspacesSchema(AgentSchema):
    workspaces = fields.Pluck(WorkspaceSchema, "name", many=True, required=True)

    class Meta(AgentSchema.Meta):
        fields = AgentSchema.Meta.fields + ('workspaces',)


class AgentCreationSchema(Schema):
    id = fields.Integer(dump_only=True)
    token = fields.String(dump_only=False, required=True)
    name = fields.String(required=True)
    workspaces = fields.Pluck(WorkspaceSchema, "name", many=True, required=True)

    class Meta:
        fields = (
            'id',
            'name',
            'token',
            'workspaces',
        )


class AgentCreationView(CreateMixin, GenericView):
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
    get_joinedloads = [Agent.workspaces, Workspace.agents]

    def _get_workspace(self, workspace_name):
        try:
            ws = Workspace.query.filter_by(name=workspace_name).one()
            if not ws.active:
                flask.abort(403, f"Disabled workspace: {workspace_name}")
            return ws
        except NoResultFound:
            flask.abort(404, f"No such workspace: {workspace_name}")

    def _perform_create(self,  data, **kwargs):
        token = data.pop('token')
        if not faraday_server.agent_token:
            # someone is trying to use the token, but no token was generated yet.
            abort(401, "Invalid Token")
        if token != faraday_server.agent_token:
            abort(401, "Invalid Token")

        workspace_names = data.pop('workspaces')

        if len(workspace_names) == 0:
            abort(
                make_response(
                    jsonify(
                        messages={
                            "json": {
                                "workspaces":
                                    "Must include one workspace at least"
                            }
                        }
                    ),
                    400
                )
            )
        workspace_names = [
            dict_["name"] for dict_ in workspace_names
        ]


        workspaces = list(
            self._get_workspace(workspace_name)
            for workspace_name in workspace_names
        )

        agent = super(AgentCreationView, self)._perform_create(data, **kwargs)
        agent.workspaces = workspaces

        db.session.add(agent)
        db.session.commit()

        return agent


class AgentCreationV3View(AgentCreationView):
    route_prefix = '/v3'
    trailing_slash = False


class ExecutorDataSchema(Schema):
    executor = fields.String(default=None)
    args = fields.Dict(default=None)


class AgentRunSchema(Schema):
    executorData = fields.Nested(
        ExecutorDataSchema(unknown=EXCLUDE),
        required=True
    )

    def __init__(self, *args, **kwargs):
        super(AgentRunSchema, self).__init__(*args, **kwargs)
        self.unknown = EXCLUDE


class AgentWithWorkspacesView(UpdateMixin,
                              DeleteMixin,
                              ReadOnlyView):
    route_base = 'agents'
    model_class = Agent
    schema_class = AgentWithWorkspacesSchema
    get_joinedloads = [Agent.creator, Agent.executors, Agent.workspaces]

    def _get_workspace(self, workspace_name):
        try:
            ws = Workspace.query.filter_by(name=workspace_name).one()
            if not ws.active:
                flask.abort(403, f"Disabled workspace: {workspace_name}")
            return ws
        except NoResultFound:
            flask.abort(404, f"No such workspace: {workspace_name}")

    def _update_object(self, obj, data, **kwargs):
        """Perform changes in the selected object

        It modifies the attributes of the SQLAlchemy model to match
        the data passed by the Marshmallow schema.

        It is common to overwrite this method to do something strange
        with some specific field. Typically the new method should call
        this one to handle the update of the rest of the fields.
        """
        workspace_names = data.pop('workspaces', '')
        partial = False if 'partial' not in kwargs else kwargs['partial']

        if len(workspace_names) == 0 and not partial:
            abort(
                make_response(
                    jsonify(
                        messages={
                            "json": {
                                "workspaces":
                                    "Must include one workspace at least"
                            }
                        }
                    ),
                    400
                )
            )

        workspace_names = [
            dict_["name"] for dict_ in workspace_names
        ]

        workspaces = list(
            self._get_workspace(workspace_name)
            for workspace_name in workspace_names
        )

        super()._update_object(obj, data)
        obj.workspaces = workspaces

        return obj


class AgentWithWorkspacesV3View(AgentWithWorkspacesView, PatchableMixin):
    route_prefix = '/v3'
    trailing_slash = False


class AgentView(ReadOnlyMultiWorkspacedView):
    route_base = 'agents'
    model_class = Agent
    schema_class = AgentSchema
    get_joinedloads = [Agent.creator, Agent.executors, Agent.workspaces]

    @route('/<int:agent_id>/', methods=['DELETE'])
    def remove_workspace(self, workspace_name, agent_id):
        """
        ---
          tags: ["Agent"]
          description: Removes a workspace from an agent
          responses:
            400:
              description: Bad request
            204:
              description: Ok
        """
        agent = self._get_object(agent_id, workspace_name)
        agent.workspaces.remove([
                                    workspace
                                    for workspace in agent.workspaces
                                    if workspace.name == workspace_name
                                ][0])
        db.session.add(agent)
        db.session.commit()
        return make_response({"description": "ok"}, 204)

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
        workspace = self._get_workspace(workspace_name)
        executor_data = data['executorData']

        try:
            executor = Executor.query.filter(Executor.name == executor_data['executor'],
                                         Executor.agent_id == agent_id).one()
            params = ', '.join([f'{key}={value}' for (key, value) in executor_data["args"].items()])
            command = Command(
                import_source="agent",
                tool=agent.name,
                command=executor.name,
                user='',
                hostname='',
                params=params,
                start_date=datetime.now(),
                workspace=workspace
            )

            agent_execution = AgentExecution(
                running=None,
                successful=None,
                message='',
                executor=executor,
                workspace_id=workspace.id,
                parameters_data=executor_data["args"],
                command=command
            )
            db.session.add(agent_execution)
            db.session.commit()

            changes_queue.put({
                'execution_id': agent_execution.id,
                'agent_id': agent.id,
                'workspace': agent_execution.workspace.name,
                'action': 'RUN',
                "executor": executor_data.get('executor'),
                "args": executor_data.get('args')
            })
        except NoResultFound as e:
            logger.exception(e)
            abort(400, "Can not find an agent execution with that id")
        else:
            return flask.jsonify({
                'command_id': command.id,
            })


class AgentV3View(AgentView):
    route_prefix = '/v3/ws/<workspace_name>/'
    trailing_slash = False

    @route('/<int:agent_id>', methods=['DELETE'])
    def remove_workspace(self, workspace_name, agent_id):
        # This endpoint is not an exception for V3, overrides logic of DELETE
        return super(AgentV3View, self).remove_workspace(workspace_name, agent_id)

    @route('/<int:agent_id>/run', methods=['POST'])
    def run_agent(self, workspace_name, agent_id):
        return super(AgentV3View, self).run_agent(workspace_name, agent_id)

    remove_workspace.__doc__ = AgentView.remove_workspace.__doc__
    run_agent.__doc__ = AgentView.run_agent.__doc__


AgentWithWorkspacesView.register(agent_api)
AgentWithWorkspacesV3View.register(agent_api)
AgentCreationView.register(agent_api)
AgentCreationV3View.register(agent_api)
AgentView.register(agent_api)
AgentV3View.register(agent_api)
