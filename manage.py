#!/usr/bin/env python


from flask_script import Manager

from server.web import app
from server.importer import ImportCouchDB
from server.commands.initdb import InitDB
from server.commands.faraday_schema_display import DatabaseSchema
from server.commands.app_urls import AppUrls

manager = Manager(app)


if __name__ == "__main__":
    manager.add_command('import_from_couchdb', ImportCouchDB())
    manager.add_command('generate_database_schemas', DatabaseSchema())
    manager.add_command('initdb', InitDB())
    manager.add_command('faraday_schema_display', DatabaseSchema())
    manager.add_command('show_urls', AppUrls())
    manager.run()
