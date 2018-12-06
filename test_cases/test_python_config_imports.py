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

    def test_couchdb_set(self):
        from server.config import couchdb
        couchdb.host = '127.0.0.1'
        couchdb.password = 'pass'
        couchdb.protocol = 'TCP'
        couchdb.port = '789'
        couchdb.ssl_port = '779'
        couchdb.user = "user"

    def test_database(self):
        from server.config import database
        try:
            self.connection_string = database.connection_string
        except AttributeError as e:
            return
        except Exception:
            raise
        else:
            raise AttributeError("connection_string should raise")

    def test_database_set(self):
        from server.config import database
        database.connection_string = "this_is_a_conn_string"

    def test_faraday_server(self):
        from server.config import faraday_server
        self.bind_address = faraday_server.bind_address
        self.port = faraday_server.port
        self.websocket_port = faraday_server.websocket_port
        try:
            self.secret_key = faraday_server.secret_key
        except AttributeError as e:
            return
        except Exception:
            raise
        else:
            raise AttributeError("secret_key should raise")

    def test_faraday_server_set(self):
        from server.config import faraday_server
        faraday_server.bind_address = '0.0.0.0'
        faraday_server.port = '5985'
        faraday_server.websocket_port = '9000'
        faraday_server.secret_key = 'secret'

    def test_ldap(self):
        from server.config import ldap
        self.admin_group = ldap.admin_group
        self.client_group = ldap.client_group
        self.disconnect_timeout = ldap.disconnect_timeout
        self.domain = ldap.domain
        self.domain_dn = ldap.domain_dn
        self.enabled = ldap.enabled
        self.pentester_group = ldap.pentester_group
        self.port = ldap.port
        self.server = ldap.server
        self.use_ldaps = ldap.use_ldaps
        self.use_start_tls = ldap.use_start_tls
        self.use_local_roles = ldap.use_local_roles
        self.default_local_role = ldap.default_local_role

    def test_ldap_set(self):
        from server.config import ldap
        ldap.admin_group = 'ag'
        ldap.client_group = 'cg'
        ldap.disconnect_timeout = 10.0
        ldap.domain = 'ex.com'
        ldap.domain_dn = 'DC=ex,DC=com'
        ldap.enabled = True
        ldap.pentester_group = 'pg'
        ldap.port = 389
        ldap.server = "127.0.0.0"
        ldap.use_ldaps = False
        ldap.use_start_tls = False
        ldap.use_local_roles = False
        ldap.default_local_role = None

    def test_ssl(self):
        from server.config import ssl
        error = ""
        try:
            self.certificate = ssl.certificate
        except AttributeError as e:
            pass
        except Exception:
            raise
        else:
            error += "ssl.certificate should raise\n"
        try:
            self.port = ssl.port
        except AttributeError as e:
            pass
        except Exception:
            raise
        else:
            error += "ssl.port should raise\n"
        try:
            self.keyfile = ssl.keyfile
        except AttributeError as e:
            return
        except Exception:
            raise
        else:
            error += "ssl.keyfile should raise\n"

        if len(error) != 0:
            raise AttributeError(error)

    def test_ssl_set(self):
        from server.config import ssl
        ssl.keyfile = '/a/file'
        ssl.certificate = 'cert'
        ssl.port = 998

    def test_storage(self):
        from server.config import storage
        self.path = storage.path

    def test_storage_set(self):
        from server.config import storage
        storage.path = "/the/path/"
