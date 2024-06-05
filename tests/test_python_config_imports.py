import unittest


class ImportTests(unittest.TestCase):

    def test_database(self):
        from faraday.server.config import database
        self.connection_string = database.connection_string

    def test_faraday_server(self):
        from faraday.server.config import faraday_server
        self.bind_address = faraday_server.bind_address
        self.port = faraday_server.port
        self.secret_key = faraday_server.secret_key

    def test_storage(self):
        from faraday.server.config import storage
        self.path = storage.path
