'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import time
import unittest
import pytest

import jwt

from faraday.server.web import get_app
from faraday.server.models import db


def endpoint():
    return 'OK'


class BaseAPITestCase:
    ENDPOINT_ROUTE = '/'

    @pytest.fixture(autouse=True)
    def load_app(self, app, test_client):
        """Use this to avoid having to use an app argument to every
        function"""
        self.flask_app = app
        self.app = test_client

    @pytest.fixture(autouse=True)
    def load_user(self, user):
        self.user = user

    @pytest.fixture(autouse=True)
    def route_endpoint(self, app):
        app.route(self.ENDPOINT_ROUTE)(endpoint)


class TestAuthentication(BaseAPITestCase, unittest.TestCase):
    """Tests related to allow/dissallow access depending of whether
    the user is logged in or not"""

    def test_401_when_getting_an_existent_view_and_not_logged(self):
        res = self.app.get('/')
        self.assertEqual(res.status_code, 401)

    def test_401_when_getting_an_existent_view_agent_token(self):
        res = self.app.get('/', headers={'authorization': 'agent 1234'})
        self.assertEqual(res.status_code, 401)

    def test_401_when_getting_an_existent_view_user_token(self):
        iat = int(time.time())
        exp = iat + 4200
        jwt_data = {'user_id': "invalid_id", 'iat': iat, 'exp': exp}
        token = jwt.encode(jwt_data, get_app().config['SECRET_KEY'], algorithm="HS512")
        res = self.app.get('/', headers={'authorization': f'token {token}'})
        self.assertEqual(res.status_code, 401)

    def test_401_when_posting_an_existent_view_and_not_logged(self):
        res = self.app.post('/', data={'data': 'data'})
        self.assertEqual(res.status_code, 401)

    def test_401_when_accessing_a_non_existent_view_and_not_logged(self):
        res = self.app.post('/dfsdfsdd', data={'data': 'data'})
        self.assertEqual(res.status_code, 401)

    def test_200_when_not_logged_but_endpoint_is_public(self):
        endpoint.is_public = True
        res = self.app.get('/')
        self.assertEqual(res.status_code, 200)
        del endpoint.is_public

    def test_401_when_logged_user_is_inactive(self):
        with self.flask_app.app_context():
            # Without this line the test breaks. Taken from
            # http://pythonhosted.org/Flask-Testing/#testing-with-sqlalchemy
            db.session.add(self.user)

            self.assertTrue(self.flask_app.user_datastore.deactivate_user(self.user))
        res = self.app.get('/')
        self.assertEqual(res.status_code, 401)

    def test_401_when_logged_user_is_deleted(self):
        with self.flask_app.app_context():
            self.flask_app.user_datastore.delete_user(self.user)
        res = self.app.get('/')
        self.assertEqual(res.status_code, 401)


class TestAuthenticationPytest(BaseAPITestCase):

    @pytest.mark.usefixtures('logged_user')
    def test_200_when_logged_in(self, test_client):
        res = test_client.get('/')
        assert res.status_code == 200


if __name__ == '__main__':
    unittest.main()
