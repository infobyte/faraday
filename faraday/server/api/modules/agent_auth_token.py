# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import flask
from flask import Blueprint
from flask_wtf.csrf import validate_csrf
from wtforms import ValidationError
from marshmallow import fields, Schema
from faraday.server.api.base import (
    GenericView,
)
from faraday.server.config import faraday_server


agent_auth_token_api = Blueprint('agent_auth_token_api', __name__)


class AgentAuthTokenSchema(Schema):
    token = fields.String(required=True)


class AgentAuthTokenView(GenericView):
    route_base = 'agent_token'
    schema_class = AgentAuthTokenSchema

    def index(self):
        return AgentAuthTokenSchema().dump(
            {'token': faraday_server.agent_token})

    def post(self):
        from faraday.server.app import save_new_agent_creation_token  # pylint:disable=import-outside-toplevel
        try:
            validate_csrf(flask.request.form.get('csrf_token'))
        except ValidationError:
            flask.abort(403)
        save_new_agent_creation_token()
        return AgentAuthTokenSchema().dump(
            {'token': faraday_server.agent_token})


AgentAuthTokenView.register(agent_auth_token_api)


# I'm Py3
