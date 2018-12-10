'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from tempfile import NamedTemporaryFile

import os
import sys
import json
import random
import string
import inspect

import pytest
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

from factory import Factory
from flask.testing import FlaskClient
from flask_principal import Identity, identity_changed
from sqlalchemy import event
from pytest_factoryboy import register

sys.path.append(os.path.abspath(os.getcwd()))
from server.app import create_app
from server.models import db
from test_cases import factories


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

        ret = super(CustomClient, self).open(*args, **kwargs)
        #Now set in flask 1.0
        #if ret.headers.get('content-type') == 'application/json':
        #    try:
        #        ret.json = json.loads(ret.data)
        #    except ValueError:
        #        ret.json = None
        return ret


def pytest_addoption(parser):
    # currently for tests using sqlite and memory have problem while using transactions
    # we need to review sqlite configuraitons for persistence using PRAGMA.
    parser.addoption('--connection-string',
                     help="Database connection string. Defaults to in-memory "
                     "sqlite if not specified:")
    parser.addoption('--ignore-nplusone', action='store_true',
                     help="Globally ignore nplusone errors")
    parser.addoption("--with-hypothesis", action="store_true",
                     dest="use_hypothesis", default=False,
                     help="Run property based tests")


def pytest_configure(config):
    if not config.option.use_hypothesis:
        config.option.markexpr = 'not hypothesis'


@pytest.fixture(scope='function')
def app(request):
    connection_string = request.config.getoption(
                    '--connection-string')

    if connection_string:
        postgres_user, postgres_password = connection_string.split('://')[1].split('@')[0].split(':')
        host = connection_string.split('://')[1].split('@')[1].split('/')[0]
        con = psycopg2.connect(dbname='postgres',
                               user=postgres_user,
                               host=host,
                               password=postgres_password)

        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        db_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase) for _ in range(20))
        cur.execute("CREATE DATABASE \"%s\"  ;" % db_name)
        connection_string = 'postgresql+psycopg2://{postgres_user}:{postgres_password}@{host}/{db_name}'.format(
            postgres_user=postgres_user,
            postgres_password=postgres_password,
            host=host,
            db_name=db_name,
        )
        con.close()
    else:
        connection_string = 'sqlite:///'

    app = create_app(db_connection_string=connection_string, testing=True)
    app.test_client_class = CustomClient

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        with ctx:
            db.session.close()
            db.engine.dispose()
        ctx.pop()
        if connection_string:
            postgres_user, postgres_password = connection_string.split('://')[1].split('@')[0].split(':')
            host = connection_string.split('://')[1].split('@')[1].split('/')[0]
            con = psycopg2.connect(dbname='postgres',
                                   user=postgres_user,
                                   host=host,
                                   password=postgres_password)

            con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cur = con.cursor()
            cur.execute("DROP DATABASE \"%s\"  ;" % db_name)

    request.addfinalizer(teardown)
    app.config['NPLUSONE_RAISE'] = not request.config.getoption(
        '--ignore-nplusone')
    return app


@pytest.fixture(scope='function')
def database(app, request):
    """Session-wide test database."""

    # Disable check_vulnerability_host_service_source_code constraint because
    # it doesn't work in sqlite
    vuln_constraints = db.metadata.tables['vulnerability'].constraints
    try:
        vuln_constraints.remove(next(
            constraint for constraint in vuln_constraints
            if constraint.name == 'check_vulnerability_host_service_source_code'))
    except StopIteration:
        pass
    db.init_app(app)
    db.create_all()

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

    options = {"bind": connection, 'binds': {}}
    session = db.create_scoped_session(options=options)

    # start the session in a SAVEPOINT...
    #session.begin_nested()

    database.session = session
    db.session = session

    for factory in enabled_factories:
        factory._meta.sqlalchemy_session = session

    def teardown():
        # rollback - everything that happened with the
        # Session above (including calls to commit())
        # is rolled back.
        # be careful with this!!!!!
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


@pytest.fixture
def test_client(app):
    return app.test_client()


def create_user(app, session, username, email, password, **kwargs):
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
    return create_user(app, session, 'test', 'user@test.com', 'password',
                       is_ldap=False)


@pytest.fixture
def ldap_user(app, session):
    return create_user(app, session, 'ldap', 'ldap@test.com', 'password',
                       is_ldap=True)


@pytest.fixture
def host_with_hostnames(host, hostname_factory):
    hostname_factory.create_batch(3, workspace=host.workspace, host=host)
    return host


def login_as(test_client, user):
    with test_client.session_transaction() as sess:
        # Without this line the test breaks. Taken from
        # http://pythonhosted.org/Flask-Testing/#testing-with-sqlalchemy
        assert user.id is not None
        db.session.add(user)
        sess['user_id'] = user.id
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
