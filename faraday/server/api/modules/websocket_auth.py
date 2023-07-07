"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import logging

# Related third party imports
import flask
from flask import (
    Blueprint,
    current_app as app,
)
from flask_classful import route
from itsdangerous import BadData, TimestampSigner
from marshmallow import Schema
from sqlalchemy.orm.exc import NoResultFound

# Local application imports
from faraday.server.models import Agent
from faraday.server.api.base import GenericWorkspacedView, get_workspace

logger = logging.getLogger(__name__)
websocket_auth_api = Blueprint('websocket_auth_api', __name__)


class WebsocketWorkspaceAuthSchema(Schema):
    pass


class WebsocketWorkspaceAuthView(GenericWorkspacedView):
    route_base = 'websocket_token'
    schema_class = WebsocketWorkspaceAuthSchema

    @route('', methods=['GET', 'POST'])
    def get(self, workspace_name):
        """
        ---
        get:
          tags: ["Token"]
          responses:
            200:
              description: Ok
        """
        workspace = get_workspace(workspace_name)
        signer = TimestampSigner(app.config['SECRET_KEY'], salt="websocket")
        token = signer.sign(str(workspace.id)).decode('utf-8')
        return {"token": token}


WebsocketWorkspaceAuthView.register(websocket_auth_api)


@websocket_auth_api.route('/v3/agent_websocket_token', methods=['POST'])
def agent_websocket_token():
    """
    ---
    post:
      tags: ["Token", "Agent"]
      description: Gives a token to establish a websocket connection. For agents logic only
      responses:
        200:
          description: Ok
    """
    agent = require_agent_token()
    return flask.jsonify({"token": generate_agent_websocket_token(agent)})


agent_websocket_token.is_public = True


def generate_agent_websocket_token(agent):
    signer = TimestampSigner(app.config['SECRET_KEY'], salt="websocket_agent")
    assert agent.id is not None
    token = signer.sign(str(agent.id))
    return token.decode()


def decode_agent_websocket_token(token):
    signer = TimestampSigner(app.config['SECRET_KEY'],
                             salt="websocket_agent")
    try:
        agent_id = signer.unsign(token, max_age=60).decode('utf-8')
    except BadData as e:
        raise ValueError("Invalid Token") from e
    agent = Agent.query.get(agent_id)
    if agent is None:
        raise ValueError("No agent found with that ID")
    return agent


def require_agent_token():
    """If the request doesn't have a valid agent token in the Authorization
    header, abort the request. Otherwise, return the corresponding agent
    """
    auth_type, token, agent = None, None, None
    if app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER'] not in flask.request.headers:
        flask.abort(401)
    header = flask.request.headers[app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER']]
    try:
        (auth_type, token) = header.split(None, 1)
    except ValueError:
        logger.warning("Authorization header does not have type")
        flask.abort(401)
    auth_type = auth_type.lower()
    if auth_type != 'agent':
        flask.abort(401)
    try:
        agent = Agent.query.filter_by(token=token).one()
    except NoResultFound:
        flask.abort(403)
    return agent
