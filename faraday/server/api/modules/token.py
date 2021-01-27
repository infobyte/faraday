import datetime
import logging

from itsdangerous import TimedJSONWebSignatureSerializer
from flask import Blueprint, g, request
from flask_security.utils import hash_data
from flask import current_app as app
from marshmallow import Schema

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
        user_id = g.user.id
        serializer = TimedJSONWebSignatureSerializer(
            app.config['SECRET_KEY'],
            salt="api_token",
            expires_in=int(faraday_server.api_token_expiration)
        )
        hashed_data = hash_data(g.user.password) if g.user.password else None
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        requested_at = datetime.datetime.now()
        audit_logger.info(f"User [{g.user.username}] requested token from IP [{user_ip}] at [{requested_at}]")
        return serializer.dumps({'user_id': user_id, "validation_check": hashed_data}).decode('utf-8')


class TokenAuthV3View(TokenAuthView):
    route_prefix = '/v3'
    trailing_slash = False


TokenAuthView.register(token_api)
TokenAuthV3View.register(token_api)
