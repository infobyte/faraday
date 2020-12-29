# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import datetime

from flask import Blueprint
from faraday.server.api.base import (
    GenericView,
)
from faraday.server.config import faraday_server
import pyotp


agent_auth_token_api = Blueprint('agent_auth_token_api', __name__)


class AgentAuthTokenView(GenericView):
    route_base = 'agent_token'

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
        totp = pyotp.TOTP(faraday_server.agent_token_secret)
        return {'token': totp.now(),
                'expires_in': totp.interval - datetime.datetime.now().timestamp() % totp.interval}


AgentAuthTokenView.register(agent_auth_token_api)


# I'm Py3
