# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import Blueprint
from marshmallow import fields
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView)
from faraday.server.models import AgentAuthToken
from faraday.server.schemas import PrimaryKeyRelatedField

agent_auth_token_api = Blueprint('agent_auth_token_api', __name__)


class AgentAuthTokenSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    creator = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')

    class Meta:
        model = AgentAuthToken
        fields = ('id', 'token', 'create_date', 'update_date', 'creator')


class AgentAuthTokenView(ReadWriteView):
    route_base = 'agent_tokens'
    model_class = AgentAuthToken
    schema_class = AgentAuthTokenSchema


AgentAuthTokenView.register(agent_auth_token_api)
