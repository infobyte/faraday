"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

# Related third party imports
import flask_login
from flask import jsonify, Blueprint
from flask_wtf.csrf import generate_csrf
from marshmallow import Schema

# Local application imports
from faraday.server.api.base import get_user_permissions, GenericView

session_api = Blueprint('session_api', __name__)


class EmptySchema(Schema):
    pass


class SessionView(GenericView):
    route_base = 'session'
    route_prefix = ''
    schema_class = EmptySchema

    def get(self):
        """
        ---
        get:
          tags: ["Informational"]
          description: Gives info about the current session
          responses:
            200:
              description: Ok
        """
        user = flask_login.current_user
        data = user.get_security_payload()
        data['csrf_token'] = generate_csrf()
        data['preferences'] = user.preferences
        data['permissions'] = get_user_permissions(user)
        data['user_id'] = user.id
        return jsonify(data)


SessionView.register(session_api)
