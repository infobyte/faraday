import unittest
from persistence.server import models
from persistence.server import server_io_exceptions
from mock import MagicMock, patch

models.FARADAY_UP = False
models.MERGE_STRATEGY = None  # this is the default :)

class ModelsTest(unittest.TestCase):

    def setUp(self):
        self.ws = 'a_workspace_name'

        self.a_host_dictionary = {u'_id': 1,
            u'id': u'a230c820aa495b9185efddeefb2037dde004c879',
            u'key': u'a230c820aa495b9185efddeefb2037dde004c879',
            u'value': {u'_id': u'a230c820aa495b9185efddeefb2037dde004c879',
                       u'_rev': u'1-e0ae3a6a956734f939e8156cefb93b06',
                       u'default_gateway': [u'', u''],
                       u'description': u'',
                       u'interfaces': [1],
                       u'metadata': {u'command_id': u'0f7afc41611c4c738bec9a5d7cee2679',
                                     u'create_time': 1475774796.317604,
                                     u'creator': u'ping',
                                     u'owner': None,
                                     u'update_action': 0,
                                     u'update_controller_action': u'No model controller call',
                                     u'update_time': 1475774796.317609,
                                     u'update_user': None},
                       u'name': u'64.233.190.138',
                       u'os': u'unknown',
                       u'owned': None,
                       u'owner': None,
                       u'services': 0,
                       u'vulns': 0}}

        self.an_interface_dictionary = {u'_id': 1,
            u'id': u'106025032df5e6142f541491ad4fb0d48ffb48ad.1a88f6a711c6a19939f2b0482e35e0cc44110d67',
            u'key': u'106025032df5e6142f541491ad4fb0d48ffb48ad.1a88f6a711c6a19939f2b0482e35e0cc44110d67',
            u'value': {u'_id': u'106025032df5e6142f541491ad4fb0d48ffb48ad.1a88f6a711c6a19939f2b0482e35e0cc44110d67',
                u'_rev': u'1-6fa35462e9da99592d12b991b6dcb853',
                u'description': u'',
                u'host_id': 1,
                u'hostnames': [],
                u'ipv4': {u'DNS': [],
                 u'address': u'8.18.111.200',
                 u'gateway': u'0.0.0.0',
                 u'mask': u'0.0.0.0'},
                u'ipv6': {u'DNS': [],
                 u'address': u'0000:0000:0000:0000:0000:0000:0000:0000',
                 u'gateway': u'0000:0000:0000:0000:0000:0000:0000:0000',
                 u'prefix': u'00'},
                u'mac': u'00:00:00:00:00:00',
                u'metadata': {u'command_id': u'cb26fd8683e34e2f933760472d599d78',
                     u'create_time': 1475782544.203349,
                     u'creator': u'Acunetix',
                     u'owner': None,
                     u'update_action': 0,
                     u'update_controller_action': u'No model controller call',
                     u'update_time': 1475782544.20335,
                     u'update_user': None},
                u'name': u'8.18.111.200',
                u'network_segment': u'',
                u'owned': None,
                u'owner': None,
                u'ports': {u'closed': None, u'filtered': None, u'opened': None}
                }
            }

        self.a_service_dictionary = {u'_id': 1,
            u'id': u'106025032df5e6142f541491ad4fb0d48ffb48ad.1a88f6a711c6a19939f2b0482e35e0cc44110d67.3e0e8cef31d59ddc80682eb294e0ba2a3d30a856',
            u'key': u'106025032df5e6142f541491ad4fb0d48ffb48ad.1a88f6a711c6a19939f2b0482e35e0cc44110d67.3e0e8cef31d59ddc80682eb294e0ba2a3d30a856',
            u'value': {u'_id': u'106025032df5e6142f541491ad4fb0d48ffb48ad.1a88f6a711c6a19939f2b0482e35e0cc44110d67.3e0e8cef31d59ddc80682eb294e0ba2a3d30a856',
                u'_rev': u'1-2a0c5720e9a1afacb3a0141492f8eb92',
                u'description': u'',
                u'metadata': {u'command_id': u'cb26fd8683e34e2f933760472d599d78',
                    u'create_time': 1475782544.203771,
                    u'creator': u'Acunetix',
                    u'owner': None,
                    u'update_action': 0,
                    u'update_controller_action': u'No model controller call',
                    u'update_time': 1475782544.203771,
                    u'update_user': None},
                u'name': u'http',
                u'owned': None,
                u'owner': None,
                u'ports': [80],
                u'protocol': u'tcp',
                u'status': u'open',
                u'version': u'Apache/2.2.23 (Unix) mod_ssl/2.2.23 OpenSSL/1.0.0-fips DAV/2 Communique/4.0.9'
                },
            u'vulns': 5
            }

        self.a_vuln_dictionary = {u'_id': 15,
            u'id': u'106025032df5e6142f541491ad4fb0d48ffb48ad.678d60bd444e47183dd2cc91177c228172b12a6a',
            u'key': u'106025032df5e6142f541491ad4fb0d48ffb48ad.678d60bd444e47183dd2cc91177c228172b12a6a',
            u'value': {u'_attachments': {},
                u'_id': u'106025032df5e6142f541491ad4fb0d48ffb48ad.678d60bd444e47183dd2cc91177c228172b12a6a',
                u'_rev': u'1-d65472af48de6f8084047e4a43f02635',
                u'confirmed': True,
                u'data': u'',
                u'desc': u'f',
                u'description': u'f',
                u'easeofresolution': u'',
                u'hostnames': u'',
                u'impact': {u'accountability': False,
                u'availability': False,
                u'confidentiality': False,
                u'integrity': False},
                u'issuetracker': {},
                u'metadata': {u'command_id': None,
                    u'create_time': 1475783779.361,
                    u'creator': u'UI Web',
                    u'owner': u'',
                    u'update_action': 0,
                    u'update_controller_action': u'UI Web New',
                    u'update_time': 1475783779.361,
                    u'update_user': u''},
                u'method': None,
                u'name': u'fff',
                u'obj_id': u'678d60bd444e47183dd2cc91177c228172b12a6a',
                u'owned': False,
                u'owner': u'',
                u'params': u'',
                u'parent': u'106025032df5e6142f541491ad4fb0d48ffb48ad',
                u'path': None,
                u'pname': None,
                u'query': None,
                u'refs': [],
                u'request': None,
                u'resolution': u'',
                u'response': None,
                u'service': u'',
                u'severity': u'critical',
                u'status': u'opened',
                u'tags': [],
                u'target': u'8.18.111.200',
                u'type': u'Vulnerability',
                u'website': None}}

        self.a_vuln_web_dictionary = {u'_id': 6,
          u'id': u'e52d5355bdfa9b628e4c44579290d64613240cca.6669fa48bff901851753bef31ccd23f175b01681.790670b8824bf95588c1a00e4e65cb3c681e94d6.e1436ad05855e7ed2240773b1f42d1037f160d20',
          u'key': u'e52d5355bdfa9b628e4c44579290d64613240cca.6669fa48bff901851753bef31ccd23f175b01681.790670b8824bf95588c1a00e4e65cb3c681e94d6.e1436ad05855e7ed2240773b1f42d1037f160d20',
          u'value': {u'_attachments': {},
              u'_id': u'e52d5355bdfa9b628e4c44579290d64613240cca.6669fa48bff901851753bef31ccd23f175b01681.790670b8824bf95588c1a00e4e65cb3c681e94d6.e1436ad05855e7ed2240773b1f42d1037f160d20',
              u'_rev': u'7-7b76c8c6c5a4b23d8c6f559db8f1299d',
              u'confirmed': False,
              u'data': None,
              u'desc': u"some description",
              u'description': u"some description",
              u'easeofresolution': None,
              u'hostnames': u'',
              u'impact': {u'accountability': None,
              u'availability': None,
              u'confidentiality': None,
              u'integrity': None},
              u'issuetracker': {},
              u'metadata': {u'command_id': u'cb26fd8683e34e2f933760472d599d78',
                   u'create_time': 1475782544.221528,
                   u'creator': u'Acunetix',
                   u'owner': None,
                   u'update_action': 0,
                   u'update_controller_action': u'No model controller call',
                   u'update_time': 1475782544.221529,
                   u'update_user': None},
              u'method': u'',
              u'name': u'Content type is not specified',
              u'obj_id': u'e1436ad05855e7ed2240773b1f42d1037f160d20',
              u'owned': None,
              u'owner': None,
              u'params': u'',
              u'parent': u'e52d5355bdfa9b628e4c44579290d64613240cca.6669fa48bff901851753bef31ccd23f175b01681.790670b8824bf95588c1a00e4e65cb3c681e94d6',
              u'path': u'/ErrorReport.aspx (758a002a44057725c87185c8818b3c06)',
              u'pname': u'',
              u'query': u'',
              u'refs': [],
              u'request': u'a request',
              u'resolution': u'',
              u'response': None,
              u'service': u'(80/tcp) http',
              u'severity': u'info',
              u'status': u'vulnerable',
              u'tags': [],
              u'target': u'200.110.216.122',
              u'type': u'VulnerabilityWeb',
              u'website': u'investors.gapinc.com'}
          }


    def test_ignore_in_changes(self):
        def server_io(): return {'ok': True, 'rev': 1, 'id': 2}
        decorated = models._ignore_in_changes(server_io)
        with patch.dict(models._LOCAL_CHANGES_ID_TO_REV, clear=True):
            json = decorated()
            self.assertEqual(models._LOCAL_CHANGES_ID_TO_REV[json['id']], json['rev'])

    def test_flatten_dictionary(self):
        flattened_host_dictionary = models._flatten_dictionary(self.a_host_dictionary)
        what_the_flattened_dict_should_look_like = {u'_id': 1,
            u'id': u'a230c820aa495b9185efddeefb2037dde004c879',
            u'_rev': u'1-e0ae3a6a956734f939e8156cefb93b06',
            u'default_gateway': [u'', u''],
            u'description': u'',
            u'interfaces': [1],
            u'metadata': {u'command_id': u'0f7afc41611c4c738bec9a5d7cee2679',
                          u'create_time': 1475774796.317604,
                          u'creator': u'ping',
                          u'owner': None,
                          u'update_action': 0,
                          u'update_controller_action': u'No model controller call',
                          u'update_time': 1475774796.317609,
                          u'update_user': None},
            u'name': u'64.233.190.138',
            u'os': u'unknown',
            u'owned': None,
            u'owner': None,
            u'services': 0,
            u'vulns': 0}

        self.assertDictEqual(flattened_host_dictionary, what_the_flattened_dict_should_look_like)

    def test_faraday_ready_objects_getter(self):
        hosts = _get_faraday_ready_objects(self.ws, [self.a_host_dictionary], 'hosts')
        interfaces = _get_faraday_ready_objects(self.ws, [self.an_interface_dictionary], 'interfaces')
        services = _get_faraday_ready_objects(self.ws, [self.a_service_dictionary], 'services')
        vulns = _get_faraday_ready_objects(self.ws, [self.a_vuln_dictionary], 'vulns')
        vulns_web = _get_faraday_ready_objects(self.ws, [self.a_vuln_dictionary], 'vulns_web']

        self.assertTrue(all[lambda h: isinstance(h, models.Host) for h in hosts])
        self.assertTrue(all[lambda i: isinstance(i, models.Interface) for h in interfaces])
        self.assertTrue(all[lambda s: isinstance(s, models.Service) for s in services])
        self.assertTrue(all[lambda v: isinstance(v, models.Vuln) for v in vulns])
        self.assertTrue(all[lambda v: isinstance(v, models.VulnWeb) for v in vulns_web])

