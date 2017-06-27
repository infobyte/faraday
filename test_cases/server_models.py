import os
import sys
import json
import unittest
sys.path.append(os.path.abspath(os.getcwd()))

from server.models import Interface

INTERFACE_TEST_CASE_1 = {"network_segment": "", "description": "", "_rev": "1-ffffffffffffffffbcb43323dfeeeeee", "owned": False, "mac": "00:00:00:00:00:00", "hostnames": None, "owner": "", "name": "192.168.1.1", "ipv4": {"mask": "0.0.0.0", "gateway": "0.0.0.0", "DNS": [], "address": "192.168.1.1"}, "ipv6": {"prefix": "00", "gateway": "0000:0000:0000:0000:0000:0000:0000:0000", "DNS": [], "address": "0000:0000:0000:0000:0000:0000:0000:0000"}, "_id": "90aa44756bd2f4fc2390f903a6f25f43216b0790.0e9d8e8deab983df5e8af607f00901e089174881", "type": "Interface", "metadata": {"update_time": 1498579348.26915, "update_user": "leonardo", "update_action": 0, "creator": "Metasploit", "create_time": 1498579348.26915, "update_controller_action": "No model controller call", "owner": "leonardo", "command_id": "f09ea09db5264f2185a6d142ecd794f2"}}


class ModelsTest(unittest.TestCase):

    def test_(self):
        interface = Interface(INTERFACE_TEST_CASE_1)
        interface.update_from_document(INTERFACE_TEST_CASE_1)
        self.assertEquals(interface.hostname, '')


if __name__ == '__main__':
    unittest.main()
