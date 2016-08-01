# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
import server.config
import server.database

from server.utils.logger import LOGGING_HANDLERS


def create_app():
    app = flask.Flask(__name__)
    configure(app)
    return app

def configure(app):
    app.debug = server.config.is_debug_mode()
    minify_json_output(app)

    @app.teardown_appcontext
    def remove_session_context(exception=None):
        server.database.teardown_context()

    # Add our logging handlers to Flask
    for handler in LOGGING_HANDLERS:
        app.logger.addHandler(handler)

def minify_json_output(app):
    class MiniJSONEncoder(flask.json.JSONEncoder):
        item_separator = ','
        key_separator = ':'

    app.json_encoder = MiniJSONEncoder
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

app = create_app()

# Load APIs
import server.api
import server.modules.info

