"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import functools
import logging

# Related third party imports
from flask import Blueprint
from flask_login import current_user
from flask_socketio import emit, disconnect

logger = logging.getLogger(__name__)

websockets = Blueprint('websockets', __name__)


def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            # Maybe we should return something more explicit
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped


@authenticated_only
def on_connect():
    logger.debug(f'{current_user.username} connected')
    emit('connected', {'data': f'{current_user.username} connected successfully to notifications namespace'})
