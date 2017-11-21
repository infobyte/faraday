#!/usr/bin/env python

import click
from server.importer import ImportCouchDB
from server.commands.initdb import InitDB
from server.commands.faraday_schema_display import DatabaseSchema
from server.commands.app_urls import show_all_urls
from server.commands.reset_db import reset_db_all
from server.commands.reports import import_external_reports

from server.web import app


@click.group()
def cli():
    pass

@click.command()
def process_reports():
    import_external_reports()

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

