"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from __future__ import absolute_import
from __future__ import print_function

import flask
from flask_security.recoverable import \
    send_reset_password_instructions

from flask import request, session, Blueprint, redirect
from flask_security.views import anonymous_user_required, login_user, after_this_request, get_post_login_redirect

from faraday.server.models import User

from faraday.server.utils.invalid_chars import remove_null_caracters

auth = Blueprint('auth', __name__)

@auth.route('/auth/forgot_password', methods= ['GET', 'POST'])
@anonymous_user_required
def forgot_password():
    if 'email' not in request.json:
        return flask.abort(status=400)
    email = request.json.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        # TODO: avoid user enumeration
        return flask.abort(status=200)
    send_reset_password_instructions(user)
    return flask.jsonify(response=dict(email=email), success=True, code=200)

forgot_password.is_public = True
