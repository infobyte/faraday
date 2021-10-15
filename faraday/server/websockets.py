import functools
from flask import Blueprint
from flask_socketio import emit, disconnect
import logging
from flask_login import current_user

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
def on_connect(self):
    logger.debug(f'{current_user.username} connected')
    emit('connected', {'data': f'{current_user.username} connected successfully to notifications namespace'})
