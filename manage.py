#!/usr/bin/env python

try:
    from flask_script import Manager
except ImportError:
    print('Flask-Script missing. Install requirements with "pip install -r requirements_server.txt')

from server.web import app
from server.importer import ImportCouchDB
from server.commands.initdb import InitDB
from server.commands.faraday_schema_display import DatabaseSchema
from server.commands.app_urls import AppUrls
from server.commands.reset_db import ResetDB
from server.commands.reports import ImporExternalReports

manager = Manager(app)


if __name__ == "__main__":
    manager.add_command('import_from_couchdb', ImportCouchDB())
    manager.add_command('generate_database_schemas', DatabaseSchema())
    manager.add_command('initdb', InitDB())
    manager.add_command('faraday_schema_display', DatabaseSchema())
    manager.add_command('show_urls', AppUrls())
    manager.add_command('reset_db', ResetDB())
    manager.add_command('process_reports', ImporExternalReports())
    manager.run()
