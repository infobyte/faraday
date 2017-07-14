# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask_security import Security, login_required, \
    SQLAlchemySessionUserDatastore

import server.config
import server.database
import server.models
from server.utils.logger import LOGGING_HANDLERS


app = flask.Flask(__name__)
app.config['SECRET_KEY'] = 'supersecret'
app.config['SECURITY_PASSWORD_SINGLE_HASH'] = True

# Setup Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(server.database.common_session,
                                                server.models.User,
                                                server.models.Role)
security = Security(app, user_datastore)

# We are exposing a RESTful API, so don't redirect a user to a login page in
# case of being unauthorized, raise a 403 error instead
@app.login_manager.unauthorized_handler
def unauthorized():
    flask.abort(403)

# Create a user to test with
@app.before_first_request
def create_user():
    server.database.init_common_db()
    user_datastore.create_user(email='matt@nobien.net', password='password')
    server.database.common_session.commit()

# Views
@app.route('/test')
@login_required
def home():
    return 'Logged in!!'


def setup():
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

# Load APIs
import server.api
import server.modules.info

