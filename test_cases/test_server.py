import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import unittest
import tempfile
from server.database import init_common_db

def endpoint():
    return 'OK'

class AuthTestCase(unittest.TestCase):

    ENDPOINT_ROUTE = '/'

    def setUp(self):
        self.db_fd, self.db_name = tempfile.mkstemp()
        os.environ['COMMON_DB_PATH'] = 'sqlite:///' + self.db_name
        from server.app import app
        app.testing = True
        self.app = app.test_client()
        app.route(self.ENDPOINT_ROUTE)(endpoint)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_name)

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
        with self.app.session_transaction() as sess:
            sess['user_id'] = 1
        res = self.app.get('/')
        self.assertEqual(res.status_code, 200)

    def test_200_when_not_logged_but_endpoint_is_public(self):
        endpoint.is_public = True
        res = self.app.get('/')
        self.assertEqual(res.status_code, 200)
        endpoint.is_public = False

if __name__ == '__main__':
    unittest.main()
