'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from flask import jsonify, session, Blueprint, current_app
from flask_wtf.csrf import generate_csrf

session_api = Blueprint('session_api', __name__)

@session_api.route('/session')
def session_info():
    user = current_app.user_datastore.get_user(session['user_id'])
    data = user.get_security_payload()
    data['csrf_token'] = generate_csrf()
    return jsonify(data)
