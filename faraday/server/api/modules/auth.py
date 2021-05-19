"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from __future__ import print_function
from __future__ import absolute_import

import flask

from werkzeug.local import LocalProxy
from werkzeug.datastructures import MultiDict
from urllib.parse import urlparse
import re
import logging

from flask import current_app as app
from flask import Blueprint, request, make_response
from flask_security.signals import reset_password_instructions_sent
from faraday.server import config

from flask_security.recoverable import generate_reset_password_token, update_password
from flask_security.views import anonymous_user_required
from flask_security.utils import send_mail, config_value, get_token_status, verify_hash
from flask_security.forms import ResetPasswordForm

from faraday.server.models import User

_security = LocalProxy(lambda: app.extensions['security'])
_datastore = LocalProxy(lambda: _security.datastore)

auth = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


@auth.route('/auth/forgot_password', methods=['POST'])
@anonymous_user_required
def forgot_password():
    """
    ---
    post:
      tags: ["User"]
      description: Send a token within an email to the user for password recovery
      responses:
        200:
          description: Ok
    """

    if not config.smtp.is_enabled():
        logger.warning('Missing SMTP Config.')
        return make_response(flask.jsonify(response=dict(message="Operation not implemented"), success=False, code=501),
                             501)

    if 'email' not in request.json:
        return make_response(flask.jsonify(response=dict(message="Operation not allowed"), success=False, code=406),
                             406)

    try:
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            return make_response(
                flask.jsonify(response=dict(email=email, message="Invalid Email"), success=False, code=400), 400)

        send_reset_password_instructions(user)
        return flask.jsonify(response=dict(email=email), success=True, code=200)
    except Exception as e:
        logger.exception(e)
        return make_response(flask.jsonify(response=dict(email=email, message="Server Error"), success=False, code=500),
                             500)


@auth.route('/auth/reset_password/<token>', methods=['POST'])
@anonymous_user_required
def reset_password(token):
    """
    ---
    post:
      tags: ["User"]
      description: Reset the user's password based on the given token
      responses:
        200:
          description: Ok
    """
    if not config.smtp.is_enabled():
        logger.warning('Missing SMTP Config.')
        return make_response(flask.jsonify(response=dict(message="Operation not implemented"), success=False, code=501),
                             501)

    try:
        if 'password' not in request.json or 'password_confirm' not in request.json:
            return make_response(flask.jsonify(response=dict(message="Invalid data provided"), success=False, code=406),
                                 406)

        expired, invalid, user = reset_password_token_status(token)

        if not user or invalid:
            invalid = True

        if invalid or expired:
            return make_response(flask.jsonify(response=dict(message="Invalid Token"), success=False, code=406), 406)
        if request.is_json:
            form = ResetPasswordForm(MultiDict(request.get_json()))
            if form.validate_on_submit() and validate_strong_password(form.password.data, form.password_confirm.data):
                update_password(user, form.password.data)
                _datastore.commit()
                return flask.jsonify(response=dict(message="Password changed successfully"), success=True, code=200)

        return make_response(flask.jsonify(response=dict(message="Bad request"), success=False, code=400), 400)

    except Exception as e:
        logger.exception(e)
        return make_response(flask.jsonify(response=dict(token=token, message="Server Error"), success=False, code=500),
                             500)


def send_reset_password_instructions(user):
    """Sends the reset password instructions email for the specified user.
    :param user: The user to send the instructions to
    """
    token = generate_reset_password_token(user)

    url_data = urlparse(request.base_url)
    reset_link = f"{url_data.scheme}://{url_data.netloc}/#resetpass/{token}/"

    if config_value('SEND_PASSWORD_RESET_EMAIL'):
        send_mail(config_value('EMAIL_SUBJECT_PASSWORD_RESET'),
                  user.email, 'reset_instructions',
                  user=user, reset_link=reset_link)

    reset_password_instructions_sent.send(
        app._get_current_object(), user=user, token=token
    )


def send_password_reset_notice(user):
    """Sends the password reset notice email for the specified user.
    :param user: The user to send the notice to
    """
    if config_value('SEND_PASSWORD_RESET_NOTICE_EMAIL'):
        send_mail(config_value('EMAIL_SUBJECT_PASSWORD_NOTICE'),
                  user.email, 'reset_notice', user=user)


def reset_password_token_status(token):
    """Returns the expired status, invalid status, and user of a password reset
    token. For example::
        expired, invalid, user, data = reset_password_token_status('...')
    :param token: The password reset token
    """
    expired, invalid, user, data = get_token_status(
        token, 'reset', 'RESET_PASSWORD', return_data=True
    )
    if not invalid and user:
        if user.password:
            if not verify_hash(data[1], user.password):
                invalid = True

    return expired, invalid, user


def validate_strong_password(password: str, password_confirm: str):
    # Regex from faraday change password feature
    r = r'^.*(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*[\d\W]).*$'
    is_valid = (password_confirm == password and re.match(r, password))
    return is_valid


forgot_password.is_public = True
reset_password.is_public = True
