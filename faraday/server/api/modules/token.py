# Standard library imports
import logging
from datetime import datetime

# Related third party imports
import flask_login
from flask import Blueprint
from marshmallow import Schema

# Local application imports
from faraday.server.api.base import GenericView
from faraday.server.app import request_user_ip

token_api = Blueprint('token_api', __name__)
audit_logger = logging.getLogger('audit')


class EmptySchema(Schema):
    pass


class TokenAuthView(GenericView):
    route_base = 'token'
    schema_class = EmptySchema

    def get(self):
        """
        ---
        get:
          tags: ["Token"]
          description: Gets a new user token
          responses:
            200:
              description: Ok
        """
        token = flask_login.current_user.get_token()
        user_ip = request_user_ip()
        requested_at = datetime.utcnow()
        audit_logger.info(f"User [{flask_login.current_user.username}] requested token from IP [{user_ip}] "
                          f"at [{requested_at}]")
        return token


TokenAuthView.register(token_api)
