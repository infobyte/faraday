# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import abort, Blueprint
from marshmallow import fields
from marshmallow.validate import OneOf
from sqlalchemy.orm.exc import NoResultFound

from faraday.server.api.base import (AutoSchema, ReadWriteWorkspacedView)
from faraday.server.models import db, Agent, AgentAuthToken
from faraday.server.schemas import PrimaryKeyRelatedField

agent_api = Blueprint('agent_api', __name__)


class AgentSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    type = fields.String(attribute='type', validate=OneOf(['shared', 'specific']))
    status = fields.String(attribute='status', validate=OneOf(['locked', 'paused', 'offline', 'running']))
    creator = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    tags = PrimaryKeyRelatedField('name', dump_only=True, many=True)

    class Meta:
        model = Agent
        fields = (
            'id', 'type', 'status', 'token',
            'description', 'version', 'projects', 'jobs',
            'tags', 'create_date', 'update_date', 'creator'
        )


class AgentView(ReadWriteWorkspacedView):
    route_base = 'agents'
    model_class = Agent
    schema_class = AgentSchema

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

        agent = super(AgentView, self)._perform_create(data, **kwargs)

        return agent


AgentView.register(agent_api)

