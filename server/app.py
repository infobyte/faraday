# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os
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
app.config['WTF_CSRF_ENABLED'] = False

# Setup Flask-Security
common_session = server.database.setup_common()
user_datastore = SQLAlchemySessionUserDatastore(common_session,
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
    if app.testing:
        return
    # server.database.init_common_db()
    user_datastore.create_user(email='matt@nobien.net',
                               password='password')
    common_session.commit()

# Make API endpoints require a login user by default. Based on
# https://stackoverflow.com/questions/13428708/best-way-to-make-flask-logins-login-required-the-default
app.view_functions['security.login'].is_public = True
app.view_functions['security.logout'].is_public = True
@app.before_request
def default_login_required():
    view = app.view_functions.get(flask.request.endpoint)
    logged_in = 'user_id' in flask.session
    if (not logged_in and not getattr(view, 'is_public', False)):
        flask.abort(403)

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

