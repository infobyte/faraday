# Standard library imports

# Related third party imports
import flask_login
from flask import (
    Blueprint,
)
from marshmallow import Schema

# Local application imports
from faraday.server.api.base import GenericView

token_api = Blueprint('token_api', __name__)


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
        return flask_login.current_user.get_token()


TokenAuthView.register(token_api)
