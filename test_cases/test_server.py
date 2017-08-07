import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import unittest
import tempfile
from server.app import create_app
from flask_security import Security, SQLAlchemyUserDatastore
from server.models import db, User, Role
from server.database import setup_common


def endpoint():
    return 'OK'


class BaseAPITestCase(unittest.TestCase):
    ENDPOINT_ROUTE = '/'

    def setUp(self):
        self.db_fd, self.db_name = tempfile.mkstemp()
        db_path = 'sqlite:///' + self.db_name
        self.flask_app = create_app(db_connection_string=db_path, testing=True)

        self.app = self.flask_app.test_client()
        self.flask_app.route(self.ENDPOINT_ROUTE)(endpoint)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_name)

    def login_as(self, user):
        with self.app.session_transaction() as sess:
            # Without this line the test breaks. Taken from
            # http://pythonhosted.org/Flask-Testing/#testing-with-sqlalchemy
            db.session.add(self.user)

            sess['user_id'] = user.id


class TestAuthentication(BaseAPITestCase):
    """Tests related to allow/dissallow access depending of whether
    the user is logged in or not"""

    def setUp(self):
        super(TestAuthentication, self).setUp()
        with self.flask_app.app_context():
            db.create_all()
            self.user = self.flask_app.user_datastore.create_user(
                email='user@test.net', password='password')
            db.session.add(self.user)
            db.session.commit()

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
