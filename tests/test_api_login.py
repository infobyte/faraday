
import pytest
from flask_security.utils import hash_password
from itsdangerous import TimedJSONWebSignatureSerializer

from faraday.server.models import User
from faraday.server.web import get_app
from tests import factories


class TestLogin:
    def test_case_bug_with_username(self, test_client, session):
        """
            When the user case does not match the one in database,
            the form is valid but no record was found in the database.
        """

        susan = factories.UserFactory.create(
                active=True,
                username='Susan',
                password=hash_password('pepito'),
                roles=['pentester'])
        session.add(susan)
        session.commit()
        # we use lower case username, but in db is Capitalized
        login_payload = {
            'email': 'Susan',
            'password': 'pepito',
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        assert 'authentication_token' in res.json['response']['user']

    def test_case_ws_with_valid_authentication_token(self, test_client, session):
        """
            Use of a valid auth token
        """

        alice = factories.UserFactory.create(
                active=True,
                username='alice',
                password=hash_password('passguord'),
                roles=['pentester'])
        session.add(alice)
        session.commit()

        ws = factories.WorkspaceFactory.create(name='wonderland')
        session.add(ws)
        session.commit()

        login_payload = {
            'email': 'alice',
            'password': 'passguord',
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        assert 'authentication_token' in res.json['response']['user']

        headers = {'Authentication-Token': res.json['response']['user']['authentication_token']}

        ws = test_client.get('/v3/ws/wonderland', headers=headers)
        assert ws.status_code == 200

    def test_case_ws_with_invalid_authentication_token(self, test_client, session):
        """
            Use of an invalid auth token
        """
        # clean cookies make sure test_client has no session
        test_client.cookie_jar.clear()
        secret_key = get_app().config['SECRET_KEY']
        alice = factories.UserFactory.create(
                active=True,
                username='alice',
                password=hash_password('passguord'),
                roles=['pentester'])
        session.add(alice)
        session.commit()

        ws = factories.WorkspaceFactory.create(name='wonderland')
        session.add(ws)
        session.commit()

        serializer = TimedJSONWebSignatureSerializer(get_app().config['SECRET_KEY'], expires_in=500, salt="token")
        token = serializer.dumps({'user_id': alice.id})

        headers = {'Authorization': b'Token ' + token}

        ws = test_client.get('/v3/ws/wonderland', headers=headers)
        assert ws.status_code == 401

    @pytest.mark.usefixtures('logged_user')
    def test_retrieve_token_from_api_and_use_it(self, test_client, session):
        res = test_client.get('/v3/token')
        cookies = [cookie.name for cookie in test_client.cookie_jar]
        assert "faraday_session_2" in cookies
        assert res.status_code == 200

        headers = {'Authorization': 'Token ' + res.json}
        ws = factories.WorkspaceFactory.create(name='wonderland')
        session.add(ws)
        session.commit()
        # clean cookies make sure test_client has no session
        test_client.cookie_jar.clear()
        res = test_client.get('/v3/ws/wonderland', headers=headers)
        assert res.status_code == 200
        assert 'Set-Cookie' not in res.headers
        cookies = [cookie.name for cookie in test_client.cookie_jar]
        assert "faraday_session_2" not in cookies

    def test_cant_retrieve_token_unauthenticated(self, test_client):
        # clean cookies make sure test_client has no session
        test_client.cookie_jar.clear()
        res = test_client.get('/v3/token')

        assert res.status_code == 401

    @pytest.mark.usefixtures('logged_user')
    def test_token_expires_after_password_change(self, test_client, session):
        user = User.query.filter_by(username="test").first()
        res = test_client.get('/v3/token')

        assert res.status_code == 200

        headers = {'Authorization': 'Token ' + res.json}

        if user:
            user.password = 'SECRET_VERY_SECRET_PASSWORD_TEST'
        session.add(user)
        session.commit()

        # clean cookies make sure test_client has no session
        test_client.cookie_jar.clear()
        res = test_client.get('/v3/ws', headers=headers)
        assert res.status_code == 401

    def test_null_caracters(self, test_client, session):
        """
            Use of a valid auth token
        """

        alice = factories.UserFactory.create(
                active=True,
                username='asdasd',
                password=hash_password('asdasd'),
                roles=['pentester'])
        session.add(alice)
        session.commit()

        ws = factories.WorkspaceFactory.create(name='wonderland')
        session.add(ws)
        session.commit()

        login_payload = {
            'email': "\x00asd\00asd\0",
            'password': "\x00asd\00asd\0",
        }
        res = test_client.post('/login', data=login_payload)
        # import ipdb; ipdb.set_trace()
        assert res.status_code == 200
        assert 'authentication_token' in res.json['response']['user']

        headers = {'Authentication-Token': res.json['response']['user']['authentication_token']}

        ws = test_client.get('/v3/ws/wonderland', headers=headers)
        assert ws.status_code == 200

    def test_login_remember_me(self, test_client, session):
        """
            When the remember me option is true, flask stores a remember_token
        """
        test_client.cookie_jar.clear()
        susan = factories.UserFactory.create(
                active=True,
                username='susan',
                password=hash_password('pepito'),
                roles=['pentester'])
        session.add(susan)
        session.commit()

        login_payload = {
            'email': 'susan',
            'password': 'pepito',
            'remember': True
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        cookies = [cookie.name for cookie in test_client.cookie_jar]
        assert "remember_token" in cookies

    def test_login_not_remember_me(self, test_client, session):
        """
            When the remember me option is false, flask dont stores a remember_token
        """

        test_client.cookie_jar.clear()
        susan = factories.UserFactory.create(
                active=True,
                username='susan',
                password=hash_password('pepito'),
                roles=['pentester'])
        session.add(susan)
        session.commit()
        login_payload = {
            'email': 'susan',
            'password': 'pepito',
            'remember': False
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        cookies = [cookie.name for cookie in test_client.cookie_jar]
        assert "remember_token" not in cookies

    def test_login_without_remember_me(self, test_client, session):
        """
            When the remember me option is missing, flask dont stores a remember_token
        """

        test_client.cookie_jar.clear()
        susan = factories.UserFactory.create(
                active=True,
                username='susan',
                password=hash_password('pepito'),
                roles=['pentester'])
        session.add(susan)
        session.commit()
        login_payload = {
            'email': 'susan',
            'password': 'pepito'
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        cookies = [cookie.name for cookie in test_client.cookie_jar]
        assert "remember_token" not in cookies
