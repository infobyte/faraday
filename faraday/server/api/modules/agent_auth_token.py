# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import datetime

from flask import Blueprint
from marshmallow import fields, Schema
from faraday.server.api.base import (
    GenericView,
)
from faraday.server.config import faraday_server
import pyotp

agent_auth_token_api = Blueprint('agent_auth_token_api', __name__)


class AgentAuthTokenSchema(Schema):
    token = fields.String(required=True)
    expires_in = fields.Float(required=True)


class AgentAuthTokenView(GenericView):
    route_base = 'agent_token'
    schema_class = AgentAuthTokenSchema

    def index(self):
        """
          ---
          get:
            summary: "Get the current TOTP token to register new agents."
            tags: ["Agent"]
            responses:
              200:
                description: Ok
                content:
                  application/json:
                    schema: AgentAuthTokenSchema
          tags: ["Agent"]
          responses:
            200:
              description: Ok
        """
        totp = pyotp.TOTP(faraday_server.agent_registration_secret)
        return AgentAuthTokenSchema().dump(
            {'token': totp.now(),
             'expires_in': totp.interval - datetime.datetime.now().timestamp() % totp.interval})


class AgentAuthTokenV3View(AgentAuthTokenView):
    route_prefix = '/v3'
    trailing_slash = False

AgentAuthTokenView.register(agent_auth_token_api)
AgentAuthTokenV3View.register(agent_auth_token_api)
