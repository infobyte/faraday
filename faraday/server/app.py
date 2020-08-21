# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import logging
import os
import string
import datetime

import requests
from itsdangerous import TimedJSONWebSignatureSerializer, SignatureExpired, BadSignature
from os.path import join
from random import SystemRandom

from faraday.server.config import LOCAL_CONFIG_FILE, copy_default_config_to_local
from faraday.server.models import User
from configparser import ConfigParser, NoSectionError, NoOptionError, DuplicateSectionError

import flask
from flask import Flask, session, g, request
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
    verify_and_update_password,
    verify_hash)
from flask_kvsession import KVSessionExtension
from simplekv.fs import FilesystemStore
from simplekv.decorator import PrefixDecorator
from flask_login import user_logged_out, user_logged_in
from nplusone.ext.flask_sqlalchemy import NPlusOne
from depot.manager import DepotManager

import faraday.server.config
# Load SQLAlchemy Events
import faraday.server.events
from faraday.server.utils.logger import LOGGING_HANDLERS
from faraday.server.utils.invalid_chars import remove_null_caracters
from faraday.server.config import CONST_FARADAY_HOME_PATH


logger = logging.getLogger(__name__)


def setup_storage_path():
    default_path = join(CONST_FARADAY_HOME_PATH, 'storage')
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

    from faraday.server.api.modules.info import info_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.commandsrun import commandsrun_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.activity_feed import activityfeed_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.credentials import credentials_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.hosts import host_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.licenses import license_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.services import services_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.session import session_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.vulns import vulns_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.vulnerability_template import vulnerability_template_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.workspaces import workspace_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.handlers import handlers_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.comments import comment_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.upload_reports import upload_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.websocket_auth import websocket_auth_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.get_exploits import exploits_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.custom_fields import custom_fields_schema_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.agent_auth_token import agent_auth_token_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.agent import agent_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.bulk_create import bulk_create_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.token import token_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.search_filter import searchfilter_api # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.preferences import preferences_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.export_data import export_data_api  # pylint:disable=import-outside-toplevel

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
    app.register_blueprint(agent_api)
    app.register_blueprint(agent_auth_token_api)
    app.register_blueprint(bulk_create_api)
    app.register_blueprint(token_api)
    app.register_blueprint(searchfilter_api)
    app.register_blueprint(preferences_api)
    app.register_blueprint(export_data_api)


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
    def unauthorized():  # pylint:disable=unused-variable
        flask.abort(403)

    def verify_token(token):
        serialized = TimedJSONWebSignatureSerializer(app.config['SECRET_KEY'], salt="api_token")
        try:
            data = serialized.loads(token)
            user_id = data["user_id"]
            user = User.query.filter_by(id=user_id).first()
            if not user or not verify_hash(data['validation_check'], user.password):
                logger.warn('Invalid authentication token. token invalid after password change')
                return None
            return user
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token


    @app.before_request
    def default_login_required(): # pylint:disable=unused-variable
        view = app.view_functions.get(flask.request.endpoint)

        if app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER'] in flask.request.headers:
            header = flask.request.headers[app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER']]
            try:
                (auth_type, token) = header.split(None, 1)
            except ValueError:
                logger.warn("Authorization header does not have type")
                flask.abort(401)
            auth_type = auth_type.lower()
            if auth_type == 'token':
                user = verify_token(token)
                if not user:
                    logger.warn('Invalid authentication token.')
                    flask.abort(401)
                logged_in = True
            elif auth_type == 'agent':
                # Don't handle the agent logic here, do it in another
                # before_request handler
                logged_in = False
            else:
                logger.warn("Invalid authorization type")
                flask.abort(401)
        else:
            # TODO use public flask_login functions
            logged_in = '_user_id' in flask.session
            user_id = session.get("_user_id")
            if logged_in:
                user = User.query.filter_by(id=user_id).first()

        if logged_in:
            assert user

        if not logged_in and not getattr(view, 'is_public', False):
            flask.abort(401)

        g.user = None
        if logged_in:
            g.user = user
            if user is None:
                logger.warn("Unknown user id {}".format(session["_user_id"]))
                del flask.session['_user_id']
                flask.abort(401)  # 403 would be better but breaks the web ui
                return

    @app.before_request
    def load_g_custom_fields(): # pylint:disable=unused-variable
        g.custom_fields = {}

    @app.after_request
    def log_queries_count(response): # pylint:disable=unused-variable
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


def save_new_agent_creation_token():
    assert os.path.exists(LOCAL_CONFIG_FILE)
    config = ConfigParser()
    config.read(LOCAL_CONFIG_FILE)
    rng = SystemRandom()
    agent_token = "".join([rng.choice(string.ascii_letters + string.digits) for _ in range(25)])
    config.set('faraday_server', 'agent_token', agent_token)
    with open(LOCAL_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)
    faraday.server.config.faraday_server.agent_token = agent_token


def expire_session(app, user):
    logger.debug("Cleanup sessions")
    session.destroy()
    KVSessionExtension(app=app).cleanup_sessions(app)


def user_logged_in_succesfull(app, user):
    user_agent = request.headers.get('User-Agent')
    if user_agent.startswith('faraday-client/'):
        HOME_URL = "https://portal.faradaysec.com/api/v1/license_check"
        params = {'version': faraday.__version__, 'key': 'white', 'client': user_agent}
        try:
            logger.debug('Send Faraday-Client license_check')
            res = requests.get(HOME_URL, params=params, timeout=1, verify=True)
            logger.debug("Faraday-Client license_check response: %s", res.text)
        except Exception as e:
            logger.warning("Error sending client license_check [%s]", e)
    # cleanup old sessions
    logger.debug("Cleanup sessions")
    KVSessionExtension(app=app).cleanup_sessions(app)

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

    if faraday.server.config.faraday_server.agent_token is None:
        save_new_agent_creation_token()

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
        'SECURITY_TOKEN_AUTHENTICATION_HEADER': 'Authorization',

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
            # 'pbkdf2_sha256',
            # 'pbkdf2_sha512',
            # 'sha256_crypt',
            # 'sha512_crypt',
        ],
        'PERMANENT_SESSION_LIFETIME': datetime.timedelta(hours=int(faraday.server.config.faraday_server.session_timeout or 12)),
        'SESSION_COOKIE_NAME': 'faraday_session_2',
        'SESSION_COOKIE_SAMESITE': 'Lax',
    })

    store = FilesystemStore(app.config['SESSION_FILE_DIR'])
    prefixed_store = PrefixDecorator('sessions_', store)
    KVSessionExtension(prefixed_store, app)
    user_logged_in.connect(user_logged_in_succesfull, app)
    user_logged_out.connect(expire_session, app)

    storage_path = faraday.server.config.storage.path
    if not storage_path:
        logger.warn('No storage section or path in the .faraday/config/server.ini. Setting the default value to .faraday/storage')
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

    from faraday.server.models import db # pylint:disable=import-outside-toplevel
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
    app.logger.propagate = False
    register_blueprints(app)
    register_handlers(app)

    app.view_functions['agent_api.AgentCreationView:post'].is_public = True

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
        self.email.data = remove_null_caracters(self.email.data)

        self.user = _datastore.get_user(self.email.data)

        if self.user is None:
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False

        self.user.password = remove_null_caracters(self.user.password)
        if not self.user.password:
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False
        self.password.data = remove_null_caracters(self.password.data)
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

