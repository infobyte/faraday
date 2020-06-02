"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from flask import jsonify, session, Blueprint, current_app
from flask_wtf.csrf import generate_csrf
from faraday.server.api.base import get_user_permissions

session_api = Blueprint('session_api', __name__)

@session_api.route('/session')
def session_info():
    user = current_app.user_datastore.get_user(session['_user_id'])  # TODO use public flask_login functions
    data = user.get_security_payload()
    data['csrf_token'] = generate_csrf()
    data['preferences'] = user.preferences
    data['permissions'] = get_user_permissions(user)
    return jsonify(data)
# I'm Py3
