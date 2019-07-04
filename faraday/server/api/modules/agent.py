# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import abort, Blueprint
from marshmallow import fields, Schema
from marshmallow.validate import OneOf
from sqlalchemy.orm.exc import NoResultFound

from faraday.server.api.base import (AutoSchema, ReadWriteWorkspacedView, UpdateWorkspacedMixin, DeleteWorkspacedMixin,
                                     CountWorkspacedMixin, ReadOnlyWorkspacedView, CreateWorkspacedMixin,
                                     GenericWorkspacedView)
from faraday.server.models import db, Agent, AgentAuthToken
from faraday.server.schemas import PrimaryKeyRelatedField

agent_api = Blueprint('agent_api', __name__)


class AgentSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    type = fields.String(validate=OneOf(['shared', 'specific']))
    status = fields.String(validate=OneOf(['locked', 'paused', 'offline', 'running']))
    creator = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    tags = PrimaryKeyRelatedField('name', dump_only=True, many=True)
    token = fields.String(dump_only=True)

    class Meta:
        model = Agent
        fields = (
            'id', 'type', 'status',
            'description', 'version',
            'projects', 'jobs',
            'tags', 'create_date',
            'update_date', 'creator',
            'token'
        )


class AgentCreationSchema(Schema):
    token = fields.String(dump_only=False)


class AgentCreationView(GenericWorkspacedView, CreateWorkspacedMixin):
    route_base = 'agent_registration'
    model_class = Agent
    schema_class = AgentCreationSchema
    is_public = True

    def _perform_create(self,  data, **kwargs):
        if 'token' in data:
            token = data.pop('token')
            try:
                db_token = db.session.query(AgentAuthToken).one()
            except NoResultFound:
                abort(401, "Invalid Token")
            if token != db_token.token:
                abort(401, "Invalid Token")
        else:
            abort(401, "Invalid Token")

        agent = super(AgentCreationView, self)._perform_create(data, **kwargs)

        return agent


class AgentView(UpdateWorkspacedMixin,
                DeleteWorkspacedMixin,
                CountWorkspacedMixin,
                ReadOnlyWorkspacedView):
    route_base = 'agent'
    model_class = Agent
    schema_class = AgentSchema
    get_joinedloads = [Agent.creator, Agent.tags]


AgentView.register(agent_api)
AgentCreationView.register(agent_api)
