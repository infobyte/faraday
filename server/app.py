# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import logging
import os
from os.path import join, expanduser

from server.models import User

try:
    # py2.7
    from configparser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    # py3
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError

import flask
from flask import Flask, session, g
from flask.json import JSONEncoder
from flask_security import (
    Security,
    SQLAlchemyUserDatastore,
)
from nplusone.ext.flask_sqlalchemy import NPlusOne
from depot.manager import DepotManager

import server.config
from server.utils.logger import LOGGING_HANDLERS
logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)


def setup_storage_path():
    default_path = join(expanduser("~"), '.faraday/storage')
    if not os.path.exists(default_path):
        logger.info('Creating directory {0}'.format(default_path))
        os.mkdir(default_path)
    config = ConfigParser()
    config.read(server.config.LOCAL_CONFIG_FILE)
    config.add_section('storage')
    config.set('storage', 'path', default_path)
    with open(server.config.LOCAL_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

    return default_path


def create_app(db_connection_string=None, testing=None):
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'supersecret'
    app.config['SECURITY_PASSWORD_SINGLE_HASH'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ['username']
    app.config['SECURITY_POST_LOGIN_VIEW'] = '/_api/session'
    app.config['SECURITY_POST_LOGOUT_VIEW'] = '/_api/login'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # app.config['SQLALCHEMY_ECHO'] = True
    app.config['SECURITY_PASSWORD_SCHEMES'] = [
        'bcrypt',  # This should be the default value
        # 'des_crypt',
        'pbkdf2_sha1',  # Used by CouchDB passwords
        # 'pbkdf2_sha256',
        # 'pbkdf2_sha512',
        # 'sha256_crypt',
        # 'sha512_crypt',
        'plaintext',  # TODO: remove it
    ]
    try:
        storage_path = server.config.storage.path
    except AttributeError:
        logger.warn('No storage section or path in the .faraday/server.ini. Setting the default value to .faraday/storage')
        storage_path = setup_storage_path()
    if not DepotManager.get('default'):
        if testing:
            DepotManager.configure('default', {
                'depot.storage_path': '/tmp'
            })
        else:
            DepotManager.configure('default', {
                'depot.storage_path': storage_path
            })
    if testing:
        app.config['TESTING'] = testing
        app.config['NPLUSONE_LOGGER'] = logging.getLogger('faraday.nplusone')
        app.config['NPLUSONE_LOG_LEVEL'] = logging.ERROR
        app.config['NPLUSONE_RAISE'] = True
        NPlusOne(app)
    try:
        app.config['SQLALCHEMY_DATABASE_URI'] = db_connection_string or server.config.database.connection_string.strip("'")
    except AttributeError:
        logger.info('Missing [database] section on server.ini. Please configure the database before running the server.')
    except NoOptionError:
        logger.info('Missing connection_string on [database] section on server.ini. Please configure the database before running the server.')

    from server.models import db
    db.init_app(app)

    # Setup Flask-Security
    app.user_datastore = SQLAlchemyUserDatastore(db,
                                                 server.models.User,
                                                 server.models.Role)
    Security(app, app.user_datastore)
    # Make API endpoints require a login user by default. Based on
    # https://stackoverflow.com/questions/13428708/best-way-to-make-flask-logins-login-required-the-default
    app.view_functions['security.login'].is_public = True
    app.view_functions['security.logout'].is_public = True

    app.debug = server.config.is_debug_mode()
    minify_json_output(app)

    for handler in LOGGING_HANDLERS:
        app.logger.addHandler(handler)

    from server.modules.info import info_api
    from server.api.modules.commandsrun import commandsrun_api
    from server.api.modules.credentials import credentials_api
    from server.api.modules.doc import doc_api
    from server.api.modules.hosts import host_api
    from server.api.modules.licenses import license_api
    from server.api.modules.services import services_api
    from server.api.modules.session import session_api
    from server.api.modules.vulns import vulns_api
    from server.api.modules.vulnerability_template import vulnerability_template_api
    from server.api.modules.workspaces import workspace_api
    app.register_blueprint(commandsrun_api)
    app.register_blueprint(credentials_api)
    app.register_blueprint(doc_api)
    app.register_blueprint(host_api)
    app.register_blueprint(info_api)
    app.register_blueprint(license_api)
    app.register_blueprint(services_api)
    app.register_blueprint(session_api)
    app.register_blueprint(vulns_api)
    app.register_blueprint(vulnerability_template_api)
    app.register_blueprint(workspace_api)

    # We are exposing a RESTful API, so don't redirect a user to a login page in
    # case of being unauthorized, raise a 403 error instead
    @app.login_manager.unauthorized_handler
    def unauthorized():
        flask.abort(403)

    @app.before_request
    def default_login_required():
        view = app.view_functions.get(flask.request.endpoint)
        logged_in = 'user_id' in flask.session
        if (not logged_in and not getattr(view, 'is_public', False)):
            flask.abort(403)

        g.user = None
        if logged_in:
            user = User.query.filter_by(id=session["user_id"]).first()
            g.user = user

    return app


def minify_json_output(app):
    class MiniJSONEncoder(JSONEncoder):
        item_separator = ','
        key_separator = ':'

    app.json_encoder = MiniJSONEncoder
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
