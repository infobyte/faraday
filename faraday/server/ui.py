import logging

from flask import (
    Blueprint,
    current_app,
    # abort,
)

ui = Blueprint('ui', __name__)

logger = logging.getLogger(__name__)


@ui.route('/')
def index():
    return current_app.send_static_file('index.html')
