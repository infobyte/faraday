import os
import sys
import pytest

sys.path.append(os.path.abspath(os.getcwd()))
from server.app import create_app
from server.models import db


@pytest.fixture(scope='session')
def app(request):
    # we use sqlite memory for tests
    test_conn_string = 'sqlite://'
    app = create_app(db_connection_string=test_conn_string, testing=True)

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
    connection = db.engine.connect()
    transaction = connection.begin()

    options = {"bind": connection, 'binds': {}}
    session = db.create_scoped_session(options=options)

    db.session = session

    def teardown():
        transaction.rollback()
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session

@pytest.fixture
def test_client(app):
    return app.test_client()


def create_user(app, username, email, password, **kwargs):
    user = app.user_datastore.create_user(username=username,
                                          email=email,
                                          password=password,
                                          **kwargs)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def user(app, session):
    return create_user(app, 'test', 'user@test.com', 'password', is_ldap=False)


@pytest.fixture
def ldap_user(app, session):
    return create_user(app, 'ldap', 'ldap@test.com', 'password', is_ldap=True)


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
