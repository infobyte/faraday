import os
import sys
import tempfile
import pytest

sys.path.append(os.path.abspath(os.getcwd()))
from server.app import create_app
from server.models import db


@pytest.fixture
def app(monkeypatch):
    db_fd, db_name = tempfile.mkstemp()
    db_path = 'sqlite:///' + db_name
    app = create_app(db_connection_string=db_path, testing=True)

    # monkeypatch.setattr('flask.current_app', app)
    # monkeypatch.setattr('flask_security.forms.current_app', app)

    with app.app_context():
        db.create_all()
        yield app#.test_client()
    os.close(db_fd)
    os.unlink(db_name)

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
def user(app):
    return create_user(app, 'test', 'user@test.com', 'password', is_ldap=False)


@pytest.fixture
def ldap_user(app):
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
