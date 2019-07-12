# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import random
import string
from ConfigParser import ConfigParser

from flask import Blueprint
from marshmallow import fields, Schema
from faraday.server.api.base import (
    GenericView,
)
from faraday.server.config import faraday_server
from faraday.server.config import LOCAL_CONFIG_FILE


agent_auth_token_api = Blueprint('agent_auth_token_api', __name__)


class AgentAuthTokenSchema(Schema):
    token = fields.String(required=True)


class AgentAuthTokenView(GenericView):
    route_base = 'agent_token'
    schema_class = AgentAuthTokenSchema

    def get(self, **kwargs):
        if not faraday_server.agent_token:
            rng = random.SystemRandom()
            faraday_server.agent_token = ''.join([rng.choice(string.ascii_letters + string.digits) for _ in range(0, 20)])
            config = ConfigParser()
            config.read(LOCAL_CONFIG_FILE)
            config.set('faraday_server', 'agent_token', faraday_server.agent_token)

            with open(LOCAL_CONFIG_FILE, 'w') as configfile:
                config.write(configfile)

        return AgentAuthTokenSchema().dump({'token': faraday_server.agent_token}).data


AgentAuthTokenView.register(agent_auth_token_api)
