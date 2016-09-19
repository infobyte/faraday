import responses
import requests
import unittest
from persistence.server import server
from persistence.server import utils
from mock import MagicMock, patch

server.FARADAY_UP = False
server.SERVER_URL = "http://s:p"
example_url = "http://just_some_url"
class ClientServerAPITests(unittest.TestCase):

    def setUp(self):
        self.ws_name = "a_ws"
        self.server_api_url = "http://s:p/_api"

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

    def test_create_serve_post_url(self):
        objid = "123456"
        server_post_url = server._create_server_post_url(self.ws_name, objid)
        self.assertEqual(self.server_api_url + '/ws/' + self.ws_name + '/doc/' + objid, server_post_url)

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
    def test_raise_cant_comm_with_server_on_wrong_response_code(self):
        url = "http://yes.com"
        responses.add(responses.GET, url, status=204)
        with self.assertRaises(server.CantCommunicateWithServerError):
            server._unsafe_io_with_server(requests.get, 200, url)

    @responses.activate
    def test_server_with_okey_request(self):
        url = "http://this-is-ok.com"
        responses.add(responses.GET, url, body='{"name": "betcha"}', status=200)
        responses.add(responses.PUT, url, body='{"ok": "true"}', status=200)
        response_get = server._unsafe_io_with_server(requests.get, 200, url)
        response_put = server._unsafe_io_with_server(requests.put, 200, url)
        self.assertEqual(response_get.text, requests.get(url).text)
        self.assertEqual(response_put.text, requests.put(url).text)

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

    @responses.activate
    def test_get(self):
        url = "http://get_url"
        responses.add(responses.GET, url, body='{"some": "object"}')
        expected_json = server._get(url)
        self.assertEqual(expected_json, {"some": "object"})

    @responses.activate
    def test_put_with_no_update(self):
        responses.add(responses.PUT, example_url, body='{"ok": "true"}', status=200)
        self.assertEqual(server._put(example_url, expected_response=200), {"ok": "true"})

    @responses.activate
    def test_put_with_update(self):
        responses.add(responses.GET, example_url, body='{"_rev": "1-asf"}')
        responses.add(responses.PUT, example_url, body='{"ok": "true"}', status=200)
        server._put(example_url, update=True, expected_response=200)
        self.assertIn("_rev", responses.calls[0].response.text)

    @responses.activate
    def test_delete_object(self):
        responses.add(responses.GET, example_url, body='{"_rev": "1-asf"}')
        responses.add(responses.DELETE, example_url, body='{"ok": "true"}', status=200)
        server._delete(example_url)
        self.assertIn("_rev", responses.calls[0].response.text)
        self.assertEqual(responses.calls[1].request.method, 'DELETE')

    def test_faraday_dictionary_dispatcher_result(self):
        mock_raw_hosts = MagicMock()
        mock_raw_hosts.return_value = {'rows': [{'a': 'host', 'value': {'stuff': 'other_stuff'}}], 'total_rows': 4}
        with patch('persistence.server.server._get_raw_hosts', mock_raw_hosts):
            list_of_dicts = server._get_faraday_ready_dictionaries('some_workspace', 'hosts', 'rows', full_table=False)
        with patch('persistence.server.server._get_raw_hosts', mock_raw_hosts):
            full_list_of_dicts = server._get_faraday_ready_dictionaries('some_workspace', 'hosts',
                                                                        'rows', full_table=True)
        self.assertTrue(len(list_of_dicts) == 1 == len(full_list_of_dicts))
        self.assertEqual(list_of_dicts, [mock_raw_hosts.return_value['rows'][0]['value']])
        self.assertEqual(full_list_of_dicts, mock_raw_hosts.return_value['rows'])

    @patch('persistence.server.server._get_raw_hosts')
    @patch('persistence.server.server._get_raw_vulns')
    @patch('persistence.server.server._get_raw_interfaces')
    @patch('persistence.server.server._get_raw_services')
    @patch('persistence.server.server._get_raw_notes')
    @patch('persistence.server.server._get_raw_credentials')
    @patch('persistence.server.server._get_raw_commands')
    def test_faraday_dictionary_dispatcher_calls(self, mock_hosts, mock_vulns, mock_interfaces,
                                                 mock_services, mock_notes, mock_credentials, mock_commands):
        # NOTE: if you finds any bugs here, i have the suspipcion that mock_host is actually mock_commands
        # i mean, the parameters names are wrong. I'd check for that. Good luck.
        server._get_faraday_ready_dictionaries('a', 'hosts', 'whatever')
        server._get_faraday_ready_dictionaries('a', 'interfaces', 'whatever')
        server._get_faraday_ready_dictionaries('a', 'vulns', 'whatever')
        server._get_faraday_ready_dictionaries('a', 'services', 'whatever')
        server._get_faraday_ready_dictionaries('a', 'notes', 'whatever')
        server._get_faraday_ready_dictionaries('a', 'credentials', 'whatever')
        server._get_faraday_ready_dictionaries('a', 'commands', 'whatever')
        mock_hosts.assert_called_once_with('a')
        mock_vulns.assert_called_once_with('a')
        mock_interfaces.assert_called_once_with('a')
        mock_services.assert_called_once_with('a')
        mock_notes.assert_called_once_with('a')
        mock_credentials.assert_called_once_with('a')
        mock_commands.assert_called_once_with('a')

    @patch('persistence.server.server.get_hosts', return_value='hosts')
    @patch('persistence.server.server.get_vulns', return_value='vulns')
    @patch('persistence.server.server.get_interfaces', return_value='interfaces')
    @patch('persistence.server.server.get_services', return_value='services')
    @patch('persistence.server.server.get_credentials', return_value='CREDENTIAL')
    @patch('persistence.server.server.get_notes', return_value='NOTE')
    @patch('persistence.server.server.get_commands', return_value='COMMAND')
    def test_get_objects(self, not_command, not_note, not_credential, not_service,
                         not_interface, not_vuln, not_host):
        obj_sign_to_mock = {'hosts': not_host, 'vulns': not_vuln, 'interfaces': not_interface,
                            'services': not_service, 'credentials': not_credential,
                            'notes': not_note, 'commands': not_command}
        for obj_sign in obj_sign_to_mock.keys():
            server.get_objects('a', obj_sign)
            obj_sign_to_mock[obj_sign].assert_called_once_with('a')
        with self.assertRaises(utils.WrongObjectSignature):
            server.get_objects('a', 'not a signature')
