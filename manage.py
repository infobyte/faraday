#!/usr/bin/env python


from flask_script import Manager

from server.web import app
from server.importer import ImportCouchDB

manager = Manager(app)


if __name__ == "__main__":
    manager.add_command('import-from-couchdb', ImportCouchDB())
    manager.run()
