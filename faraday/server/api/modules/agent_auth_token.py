# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import Blueprint
from marshmallow import fields
from faraday.server.api.base import (
    AutoSchema,
    GenericView,
)
from faraday.server.models import db, AgentAuthToken
from faraday.server.schemas import PrimaryKeyRelatedField

agent_auth_token_api = Blueprint('agent_auth_token_api', __name__)


class AgentAuthTokenSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    creator = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    update_date = fields.DateTime(dump_only=True)
    create_date = fields.DateTime(dump_only=True)
    token = fields.String(required=True)

    class Meta:
        model = AgentAuthToken
        fields = ('id', 'token', 'create_date', 'update_date', 'creator')


class AgentAuthTokenView(GenericView):
    route_base = 'agent_token'
    model_class = AgentAuthToken
    schema_class = AgentAuthTokenSchema

    def get(self, **kwargs):
        token = AgentAuthToken.query.first()
        if not token:
            # generate a random token
            token = AgentAuthToken()
            db.session.add(token)
            db.session.commit()

        return self._dump(token, kwargs)


AgentAuthTokenView.register(agent_auth_token_api)
