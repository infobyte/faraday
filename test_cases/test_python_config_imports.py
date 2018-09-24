import unittest


class ImportTests(unittest.TestCase):

    def test_couchdb(self):
        from server.config import couchdb
        self.host = couchdb.host
        self.password = couchdb.password
        self.protocol = couchdb.protocol
        self.port = couchdb.port
        self.ssl_port = couchdb.ssl_port
        self.user = couchdb.user

    def test_database(self):
        from server.config import database
        self.connection_string = database.connection_string

    def test_faraday_server(self):
        from server.config import faraday_server
        self.bind_address = faraday_server.bind_address
        self.port = faraday_server.port
        self.secret_key = faraday_server.secret_key
        self.websocket_port = faraday_server.websocket_port

    def test_ldap(self):
        from server.config import ldap
        self.admin_group = ldap.admin_group
        self.client_group = ldap.client_group
        self.disconnect_timeout = ldap.disconnect_timeout
        self.domain_dn = ldap.domain_dn
        self.enabled = ldap.enabled
        self.pentester_group = ldap.pentester_group
        self.port = ldap.port
        self.server = ldap.server
        self.use_ldaps = ldap.use_ldaps
        self.use_start_tls = ldap.use_start_tls

    def test_ssl(self):
        from server.config import ssl
        self.certificate = ssl.certificate
        self.keyfile = ssl.keyfile
        self.port = ssl.port

    def test_storage(self):
        from server.config import storage
        self.path = storage.path

