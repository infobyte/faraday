#!/usr/bin/env python

import click
import requests
from requests import ConnectionError
from sqlalchemy.exc import OperationalError

from persistence.server.server import _conf, FARADAY_UP, SERVER_URL
from server.importer import ImportCouchDB
from server.commands.initdb import InitDB
from server.commands.faraday_schema_display import DatabaseSchema
from server.commands.app_urls import show_all_urls
from server.commands.reset_db import reset_db_all
from server.commands.reports import import_external_reports

from server.web import app
from utils.logs import setUpLogger


@click.group()
def cli():
    pass


def check_faraday_server(url):
    return requests.get(url)


@click.command()
@click.option('--debug/--no-debug', default=False)
@click.option('--workspace', default=None)
@click.option('--disable-polling', default=False)
def process_reports(debug, workspace, disable_polling):
    setUpLogger(debug)
    configuration = _conf()
    url = '{0}/_api/v2/info'.format(configuration.getServerURI() if FARADAY_UP else SERVER_URL)
    with app.app_context():
        try:
            check_faraday_server(url)
            import_external_reports(workspace, disable_polling)
        except OperationalError as ex:
            print('{0}'.format(ex))
            print('Please verify database is running or configuration on server.ini!')
        except ConnectionError:
            print('Can\'t connect to {0}. Please check if the server is running.'.format(url))


@click.command()
def reset_db():
    with app.app_context():
        reset_db_all()

@click.command()
def show_urls():
    show_all_urls()

@click.command()
def faraday_schema_display():
    DatabaseSchema().run()

@click.command()
def initdb():
    with app.app_context():
        InitDB().run()

@click.command()
def import_from_couchdb():
    with app.app_context():
        ImportCouchDB().run()

@click.command()
def database_schema():
    DatabaseSchema().run()


cli.add_command(process_reports)
cli.add_command(reset_db)
cli.add_command(show_urls)
cli.add_command(faraday_schema_display)
cli.add_command(initdb)
cli.add_command(import_from_couchdb)
cli.add_command(database_schema)


if __name__ == '__main__':
    cli()

