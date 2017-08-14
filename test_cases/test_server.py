import os
import sys
import unittest
import tempfile
import pytest

sys.path.append(os.path.abspath(os.getcwd()))
from server.app import create_app
from flask_security import Security, SQLAlchemyUserDatastore
from server.models import db, User, Role
from server.database import setup_common


def endpoint():
    return 'OK'


class BaseAPITestCase(unittest.TestCase):

    @pytest.fixture(autouse=True)
    def load_app(self, app):
        """Use this to avoid having to use an app argument to every
        function"""
        self.flask_app = app
        self.app = app.test_client()

    def login_as(self, user):
        with self.app.session_transaction() as sess:
            # Without this line the test breaks. Taken from
            # http://pythonhosted.org/Flask-Testing/#testing-with-sqlalchemy
            db.session.add(self.user)

            sess['user_id'] = user.id


class TestAuthentication(BaseAPITestCase):
    """Tests related to allow/dissallow access depending of whether
    the user is logged in or not"""

    ENDPOINT_ROUTE = '/'

    @pytest.fixture(autouse=True)
    def load_user(self, user):
        self.user = user

    @pytest.fixture(autouse=True)
    def route_endpoint(self, app):
        app.route(self.ENDPOINT_ROUTE)(endpoint)

    def test_403_when_getting_an_existent_view_and_not_logged(self):
        res = self.app.get('/')
        self.assertEqual(res.status_code, 403)

    def test_403_when_posting_an_existent_view_and_not_logged(self):
        res = self.app.post('/', 'data')
        self.assertEqual(res.status_code, 403)

    def test_403_when_accessing_a_non_existent_view_and_not_logged(self):
        res = self.app.post('/dfsdfsdd', 'data')
        self.assertEqual(res.status_code, 403)

    def test_200_when_logged_in(self):
        self.login_as(self.user)
        res = self.app.get('/')
        self.assertEqual(res.status_code, 200)

    def test_200_when_not_logged_but_endpoint_is_public(self):
        endpoint.is_public = True
        res = self.app.get('/')
        self.assertEqual(res.status_code, 200)
        del endpoint.is_public

    def test_403_when_logged_user_is_inactive(self):
        with self.flask_app.app_context():
            # Without this line the test breaks. Taken from
            # http://pythonhosted.org/Flask-Testing/#testing-with-sqlalchemy
            db.session.add(self.user)

            self.assertTrue(self.flask_app.user_datastore.deactivate_user(self.user))
        res = self.app.get('/')
        self.assertEqual(res.status_code, 403)

    def test_403_when_logged_user_is_deleted(self):
        with self.flask_app.app_context():
            self.flask_app.user_datastore.delete_user(self.user)
        res = self.app.get('/')
        self.assertEqual(res.status_code, 403)


if __name__ == '__main__':
    unittest.main()
