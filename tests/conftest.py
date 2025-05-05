'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
from tempfile import NamedTemporaryFile
from time import time
import random

import json
import inspect
import pytest
from factory import Factory
from flask.testing import FlaskClient
from flask_principal import Identity, identity_changed
from pathlib import Path
from pytest_factoryboy import register
from sqlalchemy import event

import psycopg2
from psycopg2.sql import SQL

from faraday.server.app import get_app
from faraday.server.models import db, LOCAL_TYPE, LDAP_TYPE
from tests import factories


pytest_plugins = ("celery.contrib.pytest", )

TEST_DATA_PATH = Path(__file__).parent / 'data'

TEMPORATY_SQLITE = NamedTemporaryFile()
# Discover factories to automatically register them to pytest-factoryboy and to
# override its session
enabled_factories = []
for attr_name in dir(factories):
    obj = getattr(factories, attr_name)
    if not inspect.isclass(obj):
        continue
    if not issubclass(obj, Factory):
        continue
    if obj._meta.model is None:
        # It is an abstract class
        continue
    enabled_factories.append(obj)

for factory in enabled_factories:
    register(factory)

register(factories.WorkspaceFactory, "workspace")
register(factories.WorkspaceFactory, "second_workspace")


class CustomClient(FlaskClient):

    def open(self, *args, **kwargs):
        if kwargs.pop('use_json_data', True) and 'data' in kwargs:
            # JSON-encode data by default
            kwargs['data'] = json.dumps(kwargs['data'])
            kwargs['headers'] = kwargs.get('headers', []) + [
                ('Content-Type', 'application/json'),
            ]

        # Reset queries to make the log_queries_count
        from flask import _app_ctx_stack
        _app_ctx_stack.top.sqlalchemy_queries = []

        ret = super().open(*args, **kwargs)
        # Now set in flask 1.0
        # if ret.headers.get('content-type') == 'application/json':
        #    try:
        #        ret.json = json.loads(ret.data)
        #    except ValueError:
        #        ret.json = None
        return ret

    @property
    def cookies(self):
        return self.cookie_jar


def pytest_addoption(parser):
    # currently for tests using sqlite and memory have problem while using transactions
    # we need to review sqlite configuraitons for persistence using PRAGMA.
    parser.addoption('--connection-string', default=f'sqlite:////{TEMPORATY_SQLITE.name}',
                     help="Database connection string. Defaults to in-memory "
                          "sqlite if not specified:")
    parser.addoption('--ignore-nplusone', action='store_true',
                     help="Globally ignore nplusone errors")
    parser.addoption("--with-hypothesis", action="store_true",
                     dest="use_hypothesis", default=False,
                     help="Run property based tests")


def pytest_configure(config):
    if config.option.markexpr == 'hypothesis':
        return
    if not config.option.use_hypothesis:
        config.option.markexpr = 'not hypothesis'


@pytest.fixture(scope='session')
def app(request):
    db_user = os.getenv("POSTGRES_USER", None)
    db_password = os.getenv("POSTGRES_PASSWORD", None)
    db_host = os.getenv("POSTGRES_HOST", None)

    if not db_user:
        print("Please set environment variable POSTGRES_USER.")
        exit("Please set environment variable POSTGRES_USER.")

    if not db_password:
        print("Please set environment variable POSTGRES_PASSWORD.")
        exit("Please set environment variable POSTGRES_PASSWORD.")

    if not db_host:
        print("Please set environment variable POSTGRES_HOST.")
        exit("Please set environment variable POSTGRES_HOST.")

    rand_db = create_random_db(db_user, db_password, db_host)

    connection_string = f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}/{rand_db}"

    app = get_app(db_connection_string=connection_string, testing=True)
    app.test_client_class = CustomClient

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()
        drop_database(rand_db, db_user, db_password, db_host)

    request.addfinalizer(teardown)
    app.config['NPLUSONE_RAISE'] = not request.config.getoption(
        '--ignore-nplusone')
    return app


@pytest.fixture(scope='session')
def celery_app(app):
    # from faraday.server.celery_worker import celery
    from faraday.server.app import celery
    # for use celery_worker fixture
    from celery.contrib.testing import tasks  # NOQA
    return celery


@pytest.fixture(scope='session')
def database(app, request):
    """Session-wide test database."""
    def teardown():
        db.drop_all()
        db.session.close()
        db.engine.dispose()

    # Disable check_vulnerability_host_service_source_code constraint because
    # it doesn't work in sqlite
    vuln_constraints = db.metadata.tables['vulnerability'].constraints
    vuln_constraints.remove(next(
        constraint for constraint in vuln_constraints
        if constraint.name == 'check_vulnerability_host_service_source_code'))

    db.app = app
    db.create_all()
    db.engine.execute("INSERT INTO faraday_role(name, weight) "
                      "VALUES ('admin', 10),('asset_owner', 20),('pentester', 30),('client', 40);"
                      )

    request.addfinalizer(teardown)
    return db


@pytest.fixture(scope='function')
def fake_session(database, request):
    connection = database.engine.connect()
    transaction = connection.begin()

    options = {"bind": connection, 'binds': {}}
    session = db.create_scoped_session(options=options)

    database.session = session
    db.session = session

    for factory in enabled_factories:
        factory._meta.sqlalchemy_session = session

    def teardown():
        # rollback - everything that happened with the
        # Session above (including calls to commit())
        # is rolled back.
        # be careful with this!!!!!
        transaction.rollback()
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


@pytest.fixture(scope='function')
def session(database, request):
    """Use this fixture if the function being tested does a session
    rollback.

    See http://docs.sqlalchemy.org/en/latest/orm/session_transaction.html#joining-a-session-into-an-external-transaction-such-as-for-test-suites
    for further information
    """
    connection = database.engine.connect()
    transaction = connection.begin()

    options = {"bind": connection, 'binds': {}}
    session = db.create_scoped_session(options=options)

    # start the session in a SAVEPOINT...
    session.begin_nested()

    # then each time that SAVEPOINT ends, reopen it
    @event.listens_for(session, "after_transaction_end")
    def restart_savepoint(session, transaction):
        if transaction.nested and not transaction._parent.nested:
            # ensure that state is expired the way
            # session.commit() at the top level normally does
            # (optional step)
            session.expire_all()

            session.begin_nested()

    database.session = session
    db.session = session

    for factory in enabled_factories:
        factory._meta.sqlalchemy_session = session

    def teardown():
        # rollback - everything that happened with the
        # Session above (including calls to commit())
        # is rolled back.
        # be careful with this!!!!!
        transaction.rollback()
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


@pytest.fixture
def test_client(app):
    # flask.g is persisted in requests, and the werkzeug
    # CSRF checker could fail if we don't do this
    from flask import g
    try:
        del g.csrf_token
    except (NameError, AttributeError):
        pass

    return app.test_client()


def create_user(app, session, username, email, password, **kwargs):
    single_role = kwargs.pop('role', None)
    if 'roles' not in kwargs:
        kwargs['roles'] = [single_role] if single_role is not None else ['client']
    user = app.user_datastore.create_user(username=username,
                                          email=email,
                                          password=password,
                                          **kwargs)
    session.add(user)
    session.commit()
    return user


@pytest.fixture
def user(app, database, session):
    # print 'user', id(session), session
    return create_user(app, session, 'test', 'user@test.com', 'password', user_type=LOCAL_TYPE)


@pytest.fixture
def ldap_user(app, session):
    return create_user(app, session, 'ldap', 'ldap@test.com', 'password', user_type=LDAP_TYPE)


@pytest.fixture
def host_with_hostnames(host, hostname_factory):
    hostname_factory.create_batch(3, workspace=host.workspace, host=host)
    return host


def login_as(test_client, user):
    with test_client.session_transaction() as sess:
        # Without this line the test breaks. Taken from
        # http://pythonhosted.org/Flask-Testing/#testing-with-sqlalchemy
        assert user.id is not None
        sess['_user_id'] = user.fs_uniquifier  # TODO use public flask_login functions
        identity_changed.send(test_client.application,
                              identity=Identity(user.id))


@pytest.fixture
def logged_user(test_client, user):
    login_as(test_client, user)
    return user


@pytest.fixture
def ignore_nplusone(app):
    old = app.config['NPLUSONE_RAISE']
    app.config['NPLUSONE_RAISE'] = False
    yield
    app.config['NPLUSONE_RAISE'] = old


@pytest.fixture(autouse=True)
def skip_by_sql_dialect(app, request):
    dialect = db.session.bind.dialect.name
    if request.node.get_closest_marker('skip_sql_dialect'):
        if request.node.get_closest_marker('skip_sql_dialect').args[0] == dialect:
            pytest.skip(f'Skipped dialect is {dialect}')


@pytest.fixture
def csrf_token(logged_user, test_client):
    session_response = test_client.get('/session')
    return session_response.json.get('csrf_token')


def get_cursor(db_user: str, db_password: str, db_host: str):
    """
    Gets a psycopg2 cursor for the parent Database
    """
    conn = psycopg2.connect(
        dbname="postgres",
        user=db_user,
        password=db_password,
        host=db_host
    )

    conn.set_isolation_level(0)

    return conn.cursor()


def create_database(db_name: str, db_user: str, db_password: str, db_host: str):
    cur = get_cursor(db_user, db_password, db_host)

    cur.execute(
        SQL(
            f"create database {db_name};"
        )
    )
    cur.execute(
        SQL(
            f"grant all privileges on database {db_name} to {db_user};"
        )
    )
    cur.close()


def drop_database(db_name: str, db_user: str, db_password: str, db_host: str):
    cur = get_cursor(db_user, db_password, db_host)

    cur.execute(
        SQL(
            f"drop database {db_name};"
        )
    )
    cur.close()


def create_random_db(db_user, db_password, db_host):
    time_str = "".join(str(time()).split("."))
    random.seed()
    pref = random.randint(1111, 9999)

    random_db = "faraday_test_db_" + "_".join([time_str, str(pref)])
    create_database(random_db, db_user, db_password, db_host)

    return random_db
