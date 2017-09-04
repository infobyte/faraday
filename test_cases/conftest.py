import os
import sys
import json
import pytest
from flask.testing import FlaskClient
from pytest_factoryboy import register

sys.path.append(os.path.abspath(os.getcwd()))
from server.app import create_app
from server.models import db
from test_cases import factories



enabled_factories = [
    factories.WorkspaceFactory,
    factories.HostFactory,
    factories.ServiceFactory,
    factories.VulnerabilityFactory,
    factories.CredentialFactory,
]
for factory in enabled_factories:
    register(factory)


class CustomClient(FlaskClient):

    def open(self, *args, **kwargs):
        if kwargs.pop('use_json_data', True) and 'data' in kwargs:
            # JSON-encode data by default
            kwargs['data'] = json.dumps(kwargs['data'])
            kwargs['headers'] = kwargs.get('headers', []) + [
                ('Content-Type', 'application/json'),
            ]

        ret = super(CustomClient, self).open(*args, **kwargs)
        try:
            ret.json = json.loads(ret.data)
        except ValueError:
            ret.json = None
        return ret


@pytest.fixture(scope='session')
def app(request):
    # we use sqlite memory for tests
    test_conn_string = 'sqlite://'
    app = create_app(db_connection_string=test_conn_string, testing=True)
    app.test_client_class = CustomClient

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope='session')
def database(app, request):
    """Session-wide test database."""

    def teardown():
        db.drop_all()

    db.app = app
    db.create_all()

    request.addfinalizer(teardown)
    return db


@pytest.fixture(scope='function')
def session(database, request):
    connection = database.engine.connect()
    transaction = connection.begin()

    options = {"bind": connection, 'binds': {}}
    session = db.create_scoped_session(options=options)

    database.session = session
    db.session = session

    for factory in enabled_factories:
        factory._meta.sqlalchemy_session = session



    def teardown():
        transaction.rollback()
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
    return create_user(app, session, 'test', 'user@test.com', 'password', is_ldap=False)


@pytest.fixture
def ldap_user(app, session):
    return create_user(app, session, 'ldap', 'ldap@test.com', 'password', is_ldap=True)


def login_as(test_client, user):
    with test_client.session_transaction() as sess:
        # Without this line the test breaks. Taken from
        # http://pythonhosted.org/Flask-Testing/#testing-with-sqlalchemy
        db.session.add(user)
        sess['user_id'] = user.id

@pytest.fixture
def logged_user(test_client, user):
    login_as(test_client, user)
    return user
