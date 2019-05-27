# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import logging

import os
import string
import datetime
from future.builtins import range # __future__
from os.path import join, expanduser
from random import SystemRandom

from faraday.server.config import LOCAL_CONFIG_FILE, copy_default_config_to_local
from faraday.server.models import User, Vulnerability, VulnerabilityWeb, Workspace, VulnerabilityGeneric

try:
    # py2.7
    from faraday.client.configparser import ConfigParser, NoSectionError, NoOptionError, DuplicateSectionError
except ImportError:
    # py3
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError, DuplicateSectionError

import flask
from flask import Flask, session, g
from flask.json import JSONEncoder
from flask_sqlalchemy import get_debug_queries
from flask_security import (
    Security,
    SQLAlchemyUserDatastore,
)
from flask_security.forms import LoginForm
from flask_security.utils import (
    _datastore,
    get_message,
    verify_and_update_password
)
from flask_session import Session
from nplusone.ext.flask_sqlalchemy import NPlusOne
from depot.manager import DepotManager

import faraday.server.config
# Load SQLAlchemy Events
import faraday.server.events
from faraday.server.utils.logger import LOGGING_HANDLERS
logger = logging.getLogger(__name__)


def setup_storage_path():
    default_path = join(expanduser("~"), '.faraday/storage')
    if not os.path.exists(default_path):
        logger.info('Creating directory {0}'.format(default_path))
        os.mkdir(default_path)
    config = ConfigParser()
    config.read(faraday.server.config.LOCAL_CONFIG_FILE)
    try:
        config.add_section('storage')
        config.set('storage', 'path', default_path)
    except DuplicateSectionError:
        logger.info('Duplicate section storage. skipping.')
    with open(faraday.server.config.LOCAL_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

    return default_path


def register_blueprints(app):
    from faraday.server.api.modules.info import info_api
    from faraday.server.api.modules.commandsrun import commandsrun_api
    from faraday.server.api.modules.activity_feed import activityfeed_api
    from faraday.server.api.modules.credentials import credentials_api
    from faraday.server.api.modules.hosts import host_api
    from faraday.server.api.modules.licenses import license_api
    from faraday.server.api.modules.services import services_api
    from faraday.server.api.modules.session import session_api
    from faraday.server.api.modules.vulns import vulns_api
    from faraday.server.api.modules.vulnerability_template import vulnerability_template_api
    from faraday.server.api.modules.workspaces import workspace_api
    from faraday.server.api.modules.handlers import handlers_api
    from faraday.server.api.modules.comments import comment_api
    from faraday.server.api.modules.upload_reports import upload_api
    from faraday.server.api.modules.websocket_auth import websocket_auth_api
    from faraday.server.api.modules.get_exploits import exploits_api
    from faraday.server.api.modules.custom_fields import custom_fields_schema_api
    app.register_blueprint(commandsrun_api)
    app.register_blueprint(activityfeed_api)
    app.register_blueprint(credentials_api)
    app.register_blueprint(host_api)
    app.register_blueprint(info_api)
    app.register_blueprint(license_api)
    app.register_blueprint(services_api)
    app.register_blueprint(session_api)
    app.register_blueprint(vulns_api)
    app.register_blueprint(vulnerability_template_api)
    app.register_blueprint(workspace_api)
    app.register_blueprint(handlers_api)
    app.register_blueprint(comment_api)
    app.register_blueprint(upload_api)
    app.register_blueprint(websocket_auth_api)
    app.register_blueprint(exploits_api)
    app.register_blueprint(custom_fields_schema_api)


def check_testing_configuration(testing, app):
    if testing:
        app.config['SQLALCHEMY_ECHO'] = False
        app.config['TESTING'] = testing
        app.config['NPLUSONE_LOGGER'] = logging.getLogger('faraday.nplusone')
        app.config['NPLUSONE_LOG_LEVEL'] = logging.ERROR
        app.config['NPLUSONE_RAISE'] = True
        NPlusOne(app)


def register_handlers(app):
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
            flask.abort(401)

        g.user = None
        if logged_in:
            user = User.query.filter_by(id=session["user_id"]).first()
            g.user = user
            if user is None:
                logger.warn("Unknown user id {}".format(session["user_id"]))
                del flask.session['user_id']
                flask.abort(401)  # 403 would be better but breaks the web ui
                return

    @app.after_request
    def log_queries_count(response):
        if flask.request.method not in ['GET', 'HEAD']:
            # We did most optimizations for read only endpoints
            # TODO migrations: improve optimization and remove this if
            return response
        queries = get_debug_queries()
        max_query_time = max([q.duration for q in queries] or [0])
        if len(queries) > 15:
            logger.warn("Too many queries done (%s) in endpoint %s. "
                        "Maximum query time: %.2f",
                        len(queries), flask.request.endpoint, max_query_time)
            # from collections import Counter
            # print '\n\n\n'.join(
            #     map(str,Counter(q.statement for q in queries).most_common()))
        return response


def save_new_secret_key(app):
    if not os.path.exists(LOCAL_CONFIG_FILE):
        copy_default_config_to_local()
    config = ConfigParser()
    config.read(LOCAL_CONFIG_FILE)
    rng = SystemRandom()
    secret_key = "".join([rng.choice(string.ascii_letters + string.digits) for _ in range(25)])
    app.config['SECRET_KEY'] = secret_key
    try:
        config.set('faraday_server', 'secret_key', secret_key)
    except NoSectionError:
        config.add_section('faraday_server')
        config.set('faraday_server', 'secret_key', secret_key)
    with open(LOCAL_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)


def create_app(db_connection_string=None, testing=None):
    app = Flask(__name__)

    try:
        secret_key = faraday.server.config.faraday_server.secret_key
    except Exception:
        # Now when the config file does not exist it doesn't enter in this
        # condition, but it could happen in the future. TODO check
        save_new_secret_key(app)
    else:
        if secret_key is None:
            # This is what happens now when the config file doesn't exist.
            # TODO check
            save_new_secret_key(app)
        else:
            app.config['SECRET_KEY'] = secret_key

    login_failed_message = ("Invalid username or password", 'error')

    app.config.update({
        'SECURITY_PASSWORD_SINGLE_HASH': True,
        'WTF_CSRF_ENABLED': False,
        'SECURITY_USER_IDENTITY_ATTRIBUTES': ['username'],
        'SECURITY_POST_LOGIN_VIEW': '/_api/session',
        'SECURITY_POST_LOGOUT_VIEW': '/_api/login',
        'SECURITY_POST_CHANGE_VIEW': '/_api/change',
        'SECURITY_CHANGEABLE': True,
        'SECURITY_SEND_PASSWORD_CHANGE_EMAIL': False,
        'SECURITY_MSG_USER_DOES_NOT_EXIST': login_failed_message,

        # The line bellow should not be necessary because of the
        # CustomLoginForm, but i'll include it anyway.
        'SECURITY_MSG_INVALID_PASSWORD': login_failed_message,

        'SESSION_TYPE': 'filesystem',
        'SESSION_FILE_DIR': faraday.server.config.FARADAY_SERVER_SESSIONS_DIR,

        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_RECORD_QUERIES': True,
        # app.config['SQLALCHEMY_ECHO'] = True
        'SECURITY_PASSWORD_SCHEMES': [
            'bcrypt',  # This should be the default value
            # 'des_crypt',
            'pbkdf2_sha1',  # Used by CouchDB passwords
            # 'pbkdf2_sha256',
            # 'pbkdf2_sha512',
            # 'sha256_crypt',
            # 'sha512_crypt',
            'plaintext',  # TODO: remove it
        ],
        'PERMANENT_SESSION_LIFETIME': datetime.timedelta(hours=12),
    })

    storage_path = faraday.server.config.storage.path
    if not storage_path:
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

    check_testing_configuration(testing, app)

    try:
        app.config['SQLALCHEMY_DATABASE_URI'] = db_connection_string or faraday.server.config.database.connection_string.strip("'")
    except AttributeError:
        logger.info('Missing [database] section on server.ini. Please configure the database before running the server.')
    except NoOptionError:
        logger.info('Missing connection_string on [database] section on server.ini. Please configure the database before running the server.')

    from faraday.server.models import db
    db.init_app(app)
    #Session(app)

    # Setup Flask-Security
    app.user_datastore = SQLAlchemyUserDatastore(
        db,
        user_model=User,
        role_model=None)  # We won't use flask security roles feature
    Security(app, app.user_datastore, login_form=CustomLoginForm)
    # Make API endpoints require a login user by default. Based on
    # https://stackoverflow.com/questions/13428708/best-way-to-make-flask-logins-login-required-the-default
    app.view_functions['security.login'].is_public = True
    app.view_functions['security.logout'].is_public = True

    app.debug = faraday.server.config.is_debug_mode()
    minify_json_output(app)

    for handler in LOGGING_HANDLERS:
        app.logger.addHandler(handler)

    register_blueprints(app)
    register_handlers(app)

    return app


def minify_json_output(app):
    class MiniJSONEncoder(JSONEncoder):
        item_separator = ','
        key_separator = ':'

    app.json_encoder = MiniJSONEncoder
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False


class CustomLoginForm(LoginForm):
    """A login form that does shows the same error when the username
    or the password is invalid.

    The builtin form of flask_security generates different messages
    so it is possible for an attacker to enumerate usernames
    """

    def validate(self):

        # Use super of LoginForm, not super of CustomLoginForm, since I
        # want to skip the LoginForm validate logic
        if not super(LoginForm, self).validate():
            return False
        self.user = _datastore.get_user(self.email.data)

        if self.user is None:
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False
        if not self.user.password:
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False
        if not verify_and_update_password(self.password.data, self.user):
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False
        # if requires_confirmation(self.user):
        #     self.email.errors.append(get_message('CONFIRMATION_REQUIRED')[0])
        #     return False
        if not self.user.is_active:
            self.email.errors.append(get_message('DISABLED_ACCOUNT')[0])
            return False
        return True
