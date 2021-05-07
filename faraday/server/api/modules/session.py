"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from flask import jsonify, Blueprint
from flask_wtf.csrf import generate_csrf
from faraday.server.api.base import get_user_permissions
import flask_login

session_api = Blueprint('session_api', __name__)


@session_api.route('/session')
def session_info():
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
    return jsonify(data)
