import responses
import requests
import unittest
from persistence.server import server
from mock import MagicMock, patch

server.FARADAY_UP = False
server.SERVER_URL = "http://s:p"
class ClientServerAPITests(unittest.TestCase):

    def setUp(self):
        self.ws_name = "a_ws"
        self.server_api_url = server.SERVER_URL = "http://s:p/_api"

    def test_get_base_server_url(self):
        s = server._get_base_server_url()
        self.assertEqual(server.SERVER_URL, s)

    def test_create_server_api_url(self):
        s = server._create_server_api_url()
        self.assertEqual("{0}/_api".format(server.SERVER_URL), s)

    def test_create_server_get_url(self):
        obj_name = "hosts"
        s = server._create_server_get_url(self.ws_name, obj_name)
        self.assertEqual("{0}/_api/ws/{1}/{2}".format(server.SERVER_URL, self.ws_name, obj_name), s)

    def test_create_server_get_ws_names_url(self):
        s = server._create_server_get_url(self.ws_name)
        self.assertEqual("{0}/_api/ws/{1}".format(server.SERVER_URL, self.ws_name), s)

    @responses.activate
    def test_raise_conflict_in_database(self):
        url1 = "http://just_raise_conflict.com"
        responses.add(responses.PUT, url1, body='{"name": "betcha"}', status=409,
                content_type="application/json", json={'error': 'conflict'})
        with self.assertRaises(server.ConflictInDatabase):
            server._unsafe_io_with_server(requests.put, 200, url1, json={"name": "betcha"})
