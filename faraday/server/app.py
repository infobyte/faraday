"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import datetime
import logging
import os

import string
import sys
from configparser import (
    ConfigParser,
    NoSectionError,
    NoOptionError,
    DuplicateSectionError,
)
from pathlib import Path
from random import SystemRandom


# Related third party imports
import bleach
import flask
import flask_login
import jwt
import pyotp
import requests
from depot.manager import DepotManager
from flask import Flask, session, g, request
from flask.json import JSONEncoder
from flask_kvsession import KVSessionExtension
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import user_logged_out, user_logged_in
from flask_security import Security, SQLAlchemyUserDatastore
from flask_security.forms import LoginForm
from flask_security.utils import (
    _datastore,
    get_message,
    verify_and_update_password,
    verify_hash,
)
from flask_sqlalchemy import get_debug_queries
from simplekv.decorator import PrefixDecorator
from simplekv.fs import FilesystemStore
from sqlalchemy.pool import QueuePool

# Local application imports
import faraday.server.config
from faraday.server.config import faraday_server
import faraday.server.events
from faraday.server.config import (
    CONST_FARADAY_HOME_PATH,
    LOCAL_CONFIG_FILE,
    copy_default_config_to_local,
)
from faraday.server.extensions import socketio
from faraday.server.models import (
    User,
    Role,
)
from faraday.server.utils.ping import ping_home_background_task

from faraday.server.utils.reports_processor import reports_manager_background_task
from faraday.server.api.modules.swagger import swagger_api
from faraday.server.utils.invalid_chars import remove_null_characters
from faraday.server.utils.logger import LOGGING_HANDLERS
from faraday.server.websockets.dispatcher import remove_sid
from faraday.settings import load_settings
from faraday.server.extensions import celery
from faraday.server.debouncer import Debouncer

# Don't move this import from here
from nplusone.ext.flask_sqlalchemy import NPlusOne

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger('audit')

FARADAY_APP = None
DEBOUNCER = None


def setup_storage_path():
    default_path = CONST_FARADAY_HOME_PATH / 'storage'
    if not default_path.exists():
        logger.info(f'Creating directory {default_path}')
        default_path.mkdir()
    config = ConfigParser()
    config.read(faraday.server.config.LOCAL_CONFIG_FILE)
    try:
        config.add_section('storage')
        config.set('storage', 'path', str(default_path))
    except DuplicateSectionError:
        logger.info('Duplicate section storage. skipping.')
    with faraday.server.config.LOCAL_CONFIG_FILE.open('w') as configfile:
        config.write(configfile)

    return default_path


def register_blueprints(app):
    from faraday.server.ui import ui  # pylint: disable=import-outside-toplevel
    from faraday.server.api.modules.info import info_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.commandsrun import commandsrun_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.global_commands import globalcommands_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.activity_feed import activityfeed_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.credentials import credentials_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.hosts import host_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.hosts_context import host_context_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.licenses import license_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.services import services_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.services_context import services_context_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.session import session_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.vulns import vulns_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.vulns_context import vulns_context_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.vulnerability_template import \
        vulnerability_template_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.workspaces import workspace_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.handlers import handlers_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.comments import comment_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.upload_reports import upload_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.websocket_auth import websocket_auth_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.get_exploits import exploits_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.custom_fields import \
        custom_fields_schema_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.agents_schedule import agents_schedule_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.agent_auth_token import \
        agent_auth_token_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.agent import agent_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.bulk_create import bulk_create_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.token import token_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.search_filter import searchfilter_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.preferences import preferences_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.export_data import export_data_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.workflow import workflow_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.settings_reports import \
        reports_settings_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.settings_dashboard import \
        dashboard_settings_api  # pylint:disable=import-outside-toplevel
    from faraday.server.api.modules.settings_elk import \
        elk_settings_api  # pylint:disable=import-outside-toplevel

    app.register_blueprint(ui)
    app.register_blueprint(commandsrun_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(globalcommands_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(activityfeed_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(credentials_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(host_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(host_context_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(info_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(license_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(services_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(services_context_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(session_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(vulns_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(vulns_context_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(vulnerability_template_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(workspace_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(handlers_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(comment_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(upload_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(websocket_auth_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(exploits_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(custom_fields_schema_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(agent_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(agent_auth_token_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(bulk_create_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(token_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(searchfilter_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(preferences_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(export_data_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(agents_schedule_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(workflow_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(reports_settings_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(dashboard_settings_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(elk_settings_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(swagger_api, url_prefix=app.config['APPLICATION_PREFIX'])


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
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS512"])
            user_id = data["user_id"]
            user = User.query.filter_by(fs_uniquifier=user_id).first()
            if not user or not verify_hash(data['validation_check'], user.password):
                logger.warning('Invalid authentication token. token invalid after password change')
                return None
            return user
        except jwt.ExpiredSignatureError:
            return None  # valid token, but expired
        except jwt.InvalidSignatureError:
            return None  # invalid token

    @app.login_manager.request_loader
    def load_user_from_request(request):
        if app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER'] in flask.request.headers:
            header = flask.request.headers[app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER']]
            auth_type, token = None, None
            try:
                (auth_type, token) = header.split(None, 1)
            except ValueError:
                logger.warning("Authorization header does not have type")
                flask.abort(401)
            auth_type = auth_type.lower()
            if auth_type == 'token':
                user = verify_token(token)
                if not user:
                    logger.warning('Invalid authentication token.')
                    flask.abort(401)
                else:
                    return user
            elif auth_type == 'agent':
                # Don't handle the agent logic here, do it in another
                # before_request handler
                return None
            elif auth_type == "basic":
                username = flask.request.authorization.get('username', '')
                password = flask.request.authorization.get('password', '')
                user = User.query.filter_by(username=username).first()
                if user and user.verify_and_update_password(password):
                    return user
            else:
                logger.warning("Invalid authorization type")
                flask.abort(401)

        # finally, return None if both methods did not login the user
        return None

    @app.before_request
    def default_login_required():  # pylint:disable=unused-variable
        view = app.view_functions.get(flask.request.endpoint)

        if flask_login.current_user.is_anonymous and not getattr(view, 'is_public', False) \
                and flask.request.method != 'OPTIONS':
            if flask.request.endpoint not in ('ui.index', 'index', 'static'):
                flask.abort(401)

    @app.before_request
    def load_g_custom_fields():  # pylint:disable=unused-variable
        g.custom_fields = {}

    @app.after_request
    def log_queries_count(response):  # pylint:disable=unused-variable
        if flask.request.method not in ['GET', 'HEAD']:
            # We did most optimizations for read only endpoints
            # TODO migrations: improve optimization and remove this if
            return response
        queries = get_debug_queries()
        max_query_time = max([q.duration for q in queries] or [0])
        if len(queries) > 15:
            logger.warning(f"Too many queries done ({len(queries)}) in endpoint {flask.request.endpoint}. "
                           f"Maximum query time: {max_query_time:.2f}")
        return response


def save_new_secret_key(app):
    if not LOCAL_CONFIG_FILE.exists():
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
    with open(LOCAL_CONFIG_FILE, 'w', encoding='utf-8') as configfile:
        config.write(configfile)


def save_new_agent_creation_token_secret():
    assert LOCAL_CONFIG_FILE.exists()
    config = ConfigParser()
    config.read(LOCAL_CONFIG_FILE)
    registration_secret = pyotp.random_base32()
    config.set('faraday_server', 'agent_registration_secret', registration_secret)
    with open(LOCAL_CONFIG_FILE, 'w', encoding='utf-8') as configfile:
        config.write(configfile)
    faraday.server.config.faraday_server.agent_registration_secret = registration_secret


def request_user_ip():
    if not request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ.get('REMOTE_ADDR', None)
    return request.environ.get('HTTP_X_FORWARDED_FOR', None)


def expire_session(app, user):
    logger.debug("Cleanup sessions")
    session.destroy()
    KVSessionExtension(app=app).cleanup_sessions(app)

    user_ip = request_user_ip()
    user_logout_at = datetime.datetime.utcnow()
    audit_logger.info(f"User [{user.username}] logged out from IP [{user_ip}] at [{user_logout_at}]")
    logger.info(f"User [{user.username}] logged out from IP [{user_ip}] at [{user_logout_at}]")


def user_logged_in_successful(app, user):
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

    user_ip = request_user_ip()
    user_login_at = datetime.datetime.utcnow()
    audit_logger.info(f"User [{user.username}] logged in from IP [{user_ip}] at [{user_login_at}]")
    logger.info(f"User [{user.username}] logged in from IP [{user_ip}] at [{user_login_at}]")


def uia_username_mapper(identity):
    return bleach.clean(identity, strip=True)


def get_prefixed_url(app, url):
    if app.config['APPLICATION_PREFIX']:
        return f"{app.config['APPLICATION_PREFIX']}{url}"
    return url


def create_app(db_connection_string=None, testing=None, register_extensions_flag=True, start_scheduler=False, remove_sids=False):
    class CustomFlask(Flask):
        SKIP_RULES = [  # These endpoints will be removed for v3
            '/v3/ws/<workspace_name>/hosts/bulk_delete/',
            '/v3/ws/<workspace_name>/vulns/bulk_delete/',
            '/v3/ws/<workspace_id>/change_readonly/',
            '/v3/ws/<workspace_id>/deactivate/',
            '/v3/ws/<workspace_id>/activate/',
        ]

        def add_url_rule(self, rule, endpoint=None, view_func=None, **options):
            # Flask registers views when an application starts
            # do not add view from SKIP_VIEWS
            for rule_ in CustomFlask.SKIP_RULES:
                if rule_ == rule:
                    return
            return super().add_url_rule(rule, endpoint, view_func, **options)

    ui_dir = Path(__file__).parent / 'www'
    app = CustomFlask(__name__, static_folder=ui_dir.as_posix(), static_url_path='/')

    @app.errorhandler(404)
    @app.route('/', defaults={'text': ''})
    @app.route('/<path:text>')
    def index(ex):
        """
        Handles 404 errors of paths.
        :param ex: Exception to return.
        :return: The exception if the path starts with the prefixes, or the default static file.
        """
        prefixes = ('/_api', '/v3', '/socket.io')
        if request.path.startswith(prefixes):
            return ex
        return app.send_static_file('index.html')

    app.config['APPLICATION_PREFIX'] = '/_api' if not testing else ''

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

    if faraday.server.config.faraday_server.agent_registration_secret is None:
        save_new_agent_creation_token_secret()

    login_failed_message = ("Invalid username or password", 'error')

    app.config.update({
        'SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN': True,
        'SECURITY_PASSWORD_SINGLE_HASH': True,
        'WTF_CSRF_ENABLED': False,
        'SECURITY_USER_IDENTITY_ATTRIBUTES': [{'username': {'mapper': uia_username_mapper}}],
        'SECURITY_URL_PREFIX': app.config['APPLICATION_PREFIX'],
        'SECURITY_POST_LOGIN_VIEW': get_prefixed_url(app, '/session'),
        'SECURITY_POST_CHANGE_VIEW': get_prefixed_url(app, '/change'),
        # 'SECURITY_URL_PREFIX': '/_api',
        # 'SECURITY_POST_LOGIN_VIEW': '/_api/session',
        # 'SECURITY_POST_CHANGE_VIEW': '/_api/change',
        'SECURITY_RESET_PASSWORD_TEMPLATE': '/security/reset.html',
        'SECURITY_POST_RESET_VIEW': '/',
        'SECURITY_SEND_PASSWORD_RESET_EMAIL': True,
        # For testing purpose
        'SECURITY_EMAIL_SENDER': "noreply@infobytesec.com",
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
        'PERMANENT_SESSION_LIFETIME': datetime.timedelta(
            hours=int(faraday.server.config.faraday_server.session_timeout or 12)),
        'SESSION_COOKIE_NAME': 'faraday_session_2',
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'IMPORTS': ('faraday.server.tasks', ),
        'CELERY_BROKER_URL': f'redis://{faraday.server.config.faraday_server.celery_broker_url}:6379',
        'CELERY_RESULT_BACKEND': f'redis://{faraday.server.config.faraday_server.celery_backend_url}:6379',
    })

    store = FilesystemStore(app.config['SESSION_FILE_DIR'])
    prefixed_store = PrefixDecorator('sessions_', store)
    KVSessionExtension(prefixed_store, app)
    user_logged_in.connect(user_logged_in_successful, app)
    user_logged_out.connect(expire_session, app)

    storage_path = faraday.server.config.storage.path
    if not storage_path:
        logger.warning('No storage section or path in the .faraday/config/server.ini. '
                       'Setting the default value to .faraday/storage')
        storage_path = setup_storage_path()

    if not DepotManager.get('default'):
        if testing:
            DepotManager.configure('default', {
                'depot.storage_path': '/tmp'  # nosec
            })
        else:
            DepotManager.configure('default', {
                'depot.storage_path': storage_path
            })
    app.config['SQLALCHEMY_ECHO'] = 'FARADAY_LOG_QUERY' in os.environ
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'poolclass': QueuePool,
        'pool_size': 20,
        'max_overflow': 20,
        'pool_timeout': 60,
    }
    check_testing_configuration(testing, app)

    try:
        app.config[
            'SQLALCHEMY_DATABASE_URI'] = db_connection_string or faraday.server.config.database.connection_string.strip(
            "'")
    except AttributeError:
        logger.info(
            'Missing [database] section on server.ini. Please configure the database before running the server.')
    except NoOptionError:
        logger.info('Missing connection_string on [database] section on server.ini. '
                    'Please configure the database before running the server.')

    from faraday.server.models import db  # pylint:disable=import-outside-toplevel
    db.init_app(app)
    # Session(app)

    # Setup Flask-Security
    app.user_datastore = SQLAlchemyUserDatastore(
        db,
        user_model=User,
        role_model=Role)

    from faraday.server.api.modules.agent import agent_creation_api  # pylint: disable=import-outside-toplevel

    app.limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=[]
    )
    if not testing:
        app.limiter.limit(faraday.server.config.limiter_config.login_limit)(agent_creation_api)

    app.register_blueprint(agent_creation_api)

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
    app.view_functions['agent_api.AgentView:post'].is_public = True

    # Remove agents that where registered
    if not testing and remove_sids:
        with app.app_context():
            remove_sid()

    if register_extensions_flag and not register_extensions(app):
        return

    load_settings()

    if not testing and start_scheduler:
        from faraday.server.threads.crontab import CronTab  # pylint: disable=import-outside-toplevel
        agents_crontab = CronTab(app=app)
        agents_crontab.start()
    return app


def get_app(db_connection_string=None, testing=None, register_extensions_flag=True, start_scheduler=False, remove_sids=False):
    logger.debug("Calling get_app")
    global FARADAY_APP  # pylint: disable=W0603
    if not FARADAY_APP:
        FARADAY_APP = create_app(db_connection_string=db_connection_string,
                                 testing=testing,
                                 register_extensions_flag=register_extensions_flag,
                                 start_scheduler=start_scheduler,
                                 remove_sids=remove_sids)
    return FARADAY_APP


def get_debouncer():
    global DEBOUNCER  # pylint: disable=W0603
    if not DEBOUNCER:
        DEBOUNCER = Debouncer(wait=10)
    return DEBOUNCER


def register_extensions(app):
    from faraday.server.websockets.dispatcher import DispatcherNamespace  # pylint: disable=import-outside-toplevel
    socketio.init_app(app, ping_interval=faraday_server.socketio_ping_interval,
                      ping_timeout=faraday_server.socketio_ping_timeout,
                      logger=faraday_server.socketio_logger)
    socketio.on_namespace(DispatcherNamespace("/dispatcher"))

    if faraday.server.config.faraday_server.celery_enabled:
        logger.info("Celery is enabled ...")
        logger.info("Checking celery configuration ...")
        if not faraday.server.config.faraday_server.celery_broker_url:
            logger.error("No broker configuration found. Please add `celery_broker_url` to your server.ini...")
            sys.exit()
        if not faraday.server.config.faraday_server.celery_backend_url:
            logger.error("No backend configuration found. Please add `celery_backend_url` to your server.ini...")
            sys.exit()
        celery.init_app(app)
    else:
        # TODO: link to documentation with howto enable celery
        logger.info("Celery not enabled ...")
        logger.info("Starting reports processor background task ...")
        socketio.start_background_task(reports_manager_background_task)
    socketio.start_background_task(ping_home_background_task)

    return True


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

        user_ip = request_user_ip()
        time_now = datetime.datetime.utcnow()

        # Use super of LoginForm, not super of CustomLoginForm, since I
        # want to skip the LoginForm validate logic
        if not super(LoginForm, self).validate():
            audit_logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}]")
            logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}]")
            return False
        self.email.data = remove_null_characters(self.email.data)

        self.user = _datastore.find_user(username=self.email.data)

        if self.user is None:
            audit_logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                                 f"Reason: [Invalid Username]")
            logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                           f"Reason: [Invalid Username]")
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False

        self.user.password = remove_null_characters(self.user.password)
        if not self.user.password:
            audit_logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                                 f"Reason: [Invalid Password]")
            logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                           f"Reason: [Invalid Password]")
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False
        self.password.data = remove_null_characters(self.password.data)
        if not verify_and_update_password(self.password.data, self.user):
            audit_logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                                 f"Reason: [Invalid Password]")
            logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                           f"Reason: [Invalid Password]")
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False
        # if requires_confirmation(self.user):
        #     self.email.errors.append(get_message('CONFIRMATION_REQUIRED')[0])
        #     return False
        if not self.user.is_active:
            audit_logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                                 f"Reason: [Disabled Account]")
            logger.warning(f"Invalid Login - User [{self.email.data}] from IP [{user_ip}] at [{time_now}] - "
                           f"Reason: [Disabled Account]")
            self.email.errors.append(get_message('DISABLED_ACCOUNT')[0])
            return False
        return True
