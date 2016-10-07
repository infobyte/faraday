import unittest
import json
from persistence.server import models
from persistence.server import server_io_exceptions
from mock import MagicMock, patch, create_autospec

HOST_JSON_STRING = '{"_id":1,"id":"08d3b6545ec70897daf05cd471f4166a8e605c00","key":"08d3b6545ec70897daf05cd471f4166a8e605c00","value":{"_id":"08d3b6545ec70897daf05cd471f4166a8e605c00","_rev":"1-a12368dc03d557c337e833f8090db568","default_gateway":["192.168.20.1","00:1d:aa:c9:83:e8"],"description":"","interfaces":[1],"metadata":{"create_time":1475852074.455225,"creator":"","owner":"","update_action":0,"update_controller_action":"ModelControler._processAction ModelControler.newHost","update_time":1475852074.455226,"update_user":""},"name":"10.31.112.29","os":"Microsoft Windows Server 2008 R2 Standard Service Pack 1","owned":"false","owner":"","services":12,"vulns":43}}'

INTERFACE_JSON_STRING = '{"_id":1,"id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a","key":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a","value":{"_id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a","_rev":"1-c279e0906d2b1f02b832a99d5f58f99c","description":"","host_id":1,"hostnames":["qa3app09"],"ipv4":{"DNS":[],"address":"10.31.112.29","gateway":"0.0.0.0","mask":"0.0.0.0"},"ipv6":{"DNS":[],"address":"0000:0000:0000:0000:0000:0000:0000:0000","gateway":"0000:0000:0000:0000:0000:0000:0000:0000","prefix":"00"},"mac":"00:50:56:81:01:e3","metadata":{"create_time":1475852074.456803,"creator":"","owner":"","update_action":0,"update_controller_action":"ModelControler._processAction ModelControler.newInterface","update_time":1475852074.456803,"update_user":""},"name":"10.31.112.29","network_segment":"","owned":false,"owner":"","ports":{"closed":null,"filtered":null,"opened":null}}}'

SERVICE_JSON_STRING = '{"_id":1,"id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.029384202ef91fff5892042392875595fb0b41ed","key":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.029384202ef91fff5892042392875595fb0b41ed","value":{"_id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.029384202ef91fff5892042392875595fb0b41ed","_rev":"1-73ef6b9e6488fd05823b89e36bbbb626","description":"","metadata":{"create_time":1475852074.457551,"creator":"","owner":"","update_action":0,"update_controller_action":"ModelControler._processAction ModelControler.newService","update_time":1475852074.457551,"update_user":""},"name":"msrdp","owned":false,"owner":"","ports":[3389],"protocol":"tcp","status":"open","version":"unknown"},"vulns":8}'

VULN_JSON_STRING = '{"_id":8,"id":"08d3b6545ec70897daf05cd471f4166a8e605c00.2a21f3916b8c9a40e70b2fc6b7ea8f7a3a498558","key":"08d3b6545ec70897daf05cd471f4166a8e605c00.2a21f3916b8c9a40e70b2fc6b7ea8f7a3a498558","value":{"_attachments":{},"_id":"08d3b6545ec70897daf05cd471f4166a8e605c00.2a21f3916b8c9a40e70b2fc6b7ea8f7a3a498558","_rev":"1-28cb6b1372f4712dbbf7b8e1e23699e4","confirmed":false,"data":"","desc":"Each ethernet MAC address starts with a 24-bit Organizationally Unique Identifier.\\nThese OUI are registered by IEEE.\\nOutput: The following card manufacturers were identified :\\n\\n00:50:56:81:01:e3 : VMware, Inc.","description":"Each ethernet MAC address starts with a 24-bit Organizationally Unique Identifier.\\nThese OUI are registered by IEEE.\\nOutput: The following card manufacturers were identified :\\n\\n00:50:56:81:01:e3 : VMware, Inc.","easeofresolution":null,"hostnames":["qa3app09"],"impact":{"accountability":null,"availability":null,"confidentiality":null,"integrity":null},"issuetracker":{},"metadata":{"create_time":1475852074.459108,"creator":"","owner":"","update_action":0,"update_controller_action":"ModelControler._processAction ModelControler.newVuln","update_time":1475852074.459108,"update_user":""},"method":null,"name":"Ethernet Card Manufacturer Detection","obj_id":"2a21f3916b8c9a40e70b2fc6b7ea8f7a3a498558","owned":"false","owner":"","params":"","parent":"08d3b6545ec70897daf05cd471f4166a8e605c00","path":null,"pname":null,"query":null,"refs":[],"request":null,"resolution":"n/a","response":null,"service":"","severity":"info","status":"","tags":[],"target":"10.31.112.29","type":"Vulnerability","website":null}}'

VULN_WEB_JSON_STRING = '{"_id":20,"id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6.f0390f7e450cb71a4ff31e3bd38c2049c5f189f8","key":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6.f0390f7e450cb71a4ff31e3bd38c2049c5f189f8","value":{"_attachments":{},"_id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6.f0390f7e450cb71a4ff31e3bd38c2049c5f189f8","_rev":"1-aeee90afddaa938dff756baf8d2cebda","confirmed":false,"data":"","desc":"It was possible to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request.\\nOutput: A web server is running on this port.","description":"It was possible to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request.\\nOutput: A web server is running on this port.","easeofresolution":null,"hostnames":["qa3app09"],"impact":{"accountability":null,"availability":null,"confidentiality":null,"integrity":null},"issuetracker":{},"metadata":{"create_time":1475852074.464117,"creator":"","owner":"","update_action":0,"update_controller_action":"ModelControler.newVulnWeb","update_time":1475852074.464117,"update_user":""},"method":"","name":"Service Detection","obj_id":"f0390f7e450cb71a4ff31e3bd38c2049c5f189f8","owned":"false","owner":"","params":"","parent":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6","path":"","pname":"","query":"","refs":[],"request":"","resolution":"n/a","response":"","service":"(80/tcp) www","severity":"info","status":"","tags":[],"target":"10.31.112.29","type":"VulnerabilityWeb","website":"qa3app09"}}'

NOTE_JSON_STRING = '{"_id":1,"id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6.83b3a120d6928b3c1f04a41cfccc59a55c627cf2","key":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6.83b3a120d6928b3c1f04a41cfccc59a55c627cf2","value":{"_id":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6.83b3a120d6928b3c1f04a41cfccc59a55c627cf2","couchid":"08d3b6545ec70897daf05cd471f4166a8e605c00.02946afc59c50a4d76c1adbb082c2d5439baf50a.790670b8824bf95588c1a00e4e65cb3c681e94d6.83b3a120d6928b3c1f04a41cfccc59a55c627cf2","description":"","metadata":{"create_time":1475852074.461232,"creator":"","owner":"","update_action":0,"update_controller_action":"ModelControler._processAction ModelControler.newNote","update_time":1475852074.461232,"update_user":""},"name":"website","owned":false,"owner":"","text":""}}'

models.FARADAY_UP = False
models.MERGE_STRATEGY = None  # this is the default :)

class ModelsTest(unittest.TestCase):

    def setUp(self):
        self.ws = 'a_workspace_name'
        self.a_host_dictionary = json.loads(HOST_JSON_STRING)
        self.an_interface_dictionary = json.loads(INTERFACE_JSON_STRING)
        self.a_service_dictionary = json.loads(SERVICE_JSON_STRING)
        self.a_vuln_dictionary = json.loads(VULN_JSON_STRING)
        self.a_vuln_web_dictionary = json.loads(VULN_WEB_JSON_STRING)
        self.a_note_dictionary = json.loads(NOTE_JSON_STRING)

        self.maxDiff = None  # show the diff when test run no matter how big

    def test_ignore_in_changes(self):
        def server_io(): return {'ok': True, 'rev': 1, 'id': 2}
        decorated = models._ignore_in_changes(server_io)
        with patch.dict(models._LOCAL_CHANGES_ID_TO_REV, clear=True):
            json = decorated()
            self.assertEqual(models._LOCAL_CHANGES_ID_TO_REV[json['id']], json['rev'])

    def test_flatten_dictionary(self):
        flattened_host_dictionary = models._flatten_dictionary(self.a_host_dictionary)
        what_the_flattened_dict_should_look_like = {
                u"_id":1,
                u"id":u"08d3b6545ec70897daf05cd471f4166a8e605c00",
                u"_rev":u"1-a12368dc03d557c337e833f8090db568",
                u"default_gateway":[u"192.168.20.1",u"00:1d:aa:c9:83:e8"],
                u"description":u"",
                u"interfaces":[1],
                u"metadata":{u"create_time":1475852074.455225,
                             u"creator":u"",
                             u"owner":u"",
                             u"update_action":0,
                             u"update_controller_action":u"ModelControler._processAction ModelControler.newHost",
                             u"update_time":1475852074.455226,
                             u"update_user":u""},
                u"name":u"10.31.112.29",
                u"os":u"Microsoft Windows Server 2008 R2 Standard Service Pack 1",
                u"owned": u'false',
                u"owner":u"",
                u"services":12,
                u"vulns":43}

        self.assertDictEqual(flattened_host_dictionary, what_the_flattened_dict_should_look_like)

    def test_faraday_ready_objects_getter(self):
        hosts = models._get_faraday_ready_objects(self.ws, [self.a_host_dictionary], 'hosts')
        interfaces = models._get_faraday_ready_objects(self.ws, [self.an_interface_dictionary], 'interfaces')
        services = models._get_faraday_ready_objects(self.ws, [self.a_service_dictionary], 'services')
        vulns = models._get_faraday_ready_objects(self.ws, [self.a_vuln_dictionary], 'vulns')
        vulns_web = models._get_faraday_ready_objects(self.ws, [self.a_vuln_dictionary], 'vulns_web')

        self.assertTrue(all([isinstance(h, models.Host) for h in hosts]))
        self.assertTrue(all([isinstance(i, models.Interface) for i in interfaces]))
        self.assertTrue(all([isinstance(s, models.Service) for s in services]))
        self.assertTrue(all([isinstance(v, models.Vuln) for v in vulns]))
        self.assertTrue(all([isinstance(v, models.VulnWeb) for v in vulns_web]))

    def test_id_creation(self):
        # ideally, the flatten dictionary should be provided and shouldnt depend upon
        # our implementation.
        # ideally.
        classes = [models.Host, models.Interface, models.Service, models.Vuln, models.VulnWeb, models.Note]
        dicts = [self.a_host_dictionary, self.an_interface_dictionary, self.a_service_dictionary,
                 self.a_vuln_dictionary, self.a_vuln_web_dictionary, self.a_note_dictionary]
        dicts = map(models._flatten_dictionary, dicts)
        for class_, dictionary in zip(classes, dicts):
            expected_id = dictionary['id']
            parent_id = '.'.join(expected_id.split('.')[:-1])
            obj = class_(dictionary, self.ws)
            obj.setID(parent_id)
            self.assertEqual(expected_id, unicode(obj.id))
