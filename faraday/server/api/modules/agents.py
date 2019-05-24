# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import Blueprint
from marshmallow import fields
from marshmallow.validate import OneOf

from faraday.server.api.base import (AutoSchema, ReadWriteWorkspacedView)
from faraday.server.models import Agent
from faraday.server.schemas import PrimaryKeyRelatedField

agent_api = Blueprint('agent_api', __name__)


class AgentSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    type = fields.String(attribute='type', validate=OneOf(['shared', 'specific']))
    status = fields.String(attribute='status', validate=OneOf(['locked', 'pause', 'offline']))
    creator = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')

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


AgentView.register(agent_api)

