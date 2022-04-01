# Standard library imports
import datetime
import logging
import time

# Related third party imports
import flask_login
from flask import (
    Blueprint,
    request,
    current_app as app,
)
from flask_security.utils import hash_data
from marshmallow import Schema
import jwt

# Local application imports
from faraday.server.config import faraday_server
from faraday.server.api.base import GenericView

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
        user_id = flask_login.current_user.fs_uniquifier
        hashed_data = hash_data(flask_login.current_user.password) if flask_login.current_user.password else None
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        requested_at = datetime.datetime.utcnow()
        iat = int(time.time())
        exp = iat + int(faraday_server.api_token_expiration)
        jwt_data = {'user_id': user_id, "validation_check": hashed_data, 'iat': iat, 'exp': exp}
        audit_logger.info(f"User [{flask_login.current_user.username}] requested token from IP [{user_ip}] at "
                          f"[{requested_at}]")
        return jwt.encode(jwt_data, app.config['SECRET_KEY'], algorithm="HS512")


TokenAuthView.register(token_api)
