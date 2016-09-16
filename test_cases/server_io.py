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
        url = "http://just_raise_conflict.com"
        responses.add(responses.PUT, url, body='{"name": "betcha"}', status=409,
                content_type="application/json", json={'error': 'conflict'})
        with self.assertRaises(server.ConflictInDatabase):
            server._unsafe_io_with_server(requests.put, 200, url, json={"name": "betcha"})

    @responses.activate
    def test_raise_resource_does_not_exist(self):
        url = "http://dont_exist.com"
        responses.add(responses.GET, url, body='{"name": "betcha"}', status=404)
        with self.assertRaises(server.ResourceDoesNotExist):
            server._unsafe_io_with_server(requests.get, 200, url, json={"name": "betcha"})

    @responses.activate
    def test_raise_unauthorized(self):
        url = "http://nope.com"
        responses.add(responses.GET, url, body='{"name": "betcha"}', status=403)
        with self.assertRaises(server.Unauthorized):
            server._unsafe_io_with_server(requests.get, 200, url, json={"name": "betcha"})
        url2 = "http://nope2.com"
        responses.add(responses.GET, url2, body='{"name": "betcha"}', status=401)
        with self.assertRaises(server.Unauthorized):
            server._unsafe_io_with_server(requests.get, 200, url, json={"name": "betcha"})

    @responses.activate
    def test_json_parsing(self):
        url = "http://give_me_json.com"
        responses.add(responses.GET, url, body='{"some": "valid", "json": "string"}')
        url2 = "http://give_me_invalid_json.com"
        responses.add(responses.GET, url2, body='{"this is not", "valid": "json"}')
        json_as_dict = server._parse_json(requests.get(url))
        json_as_empty_dict = server._parse_json(requests.get(url2))
        self.assertEqual({'some': 'valid', 'json': 'string'}, json_as_dict)
        self.assertEqual({}, json_as_empty_dict)
