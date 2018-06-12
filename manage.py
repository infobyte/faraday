#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import re

import click
import requests
import sys

import server.config
from persistence.server.server import _conf, FARADAY_UP, SERVER_URL
from server.commands.initdb import InitDB
from server.commands.faraday_schema_display import DatabaseSchema
from server.commands.app_urls import show_all_urls
from server.commands.reports import import_external_reports
from server.commands.status_check import full_status_check
from server.models import db, User
from server.importer import ImportCouchDB

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
@click.option('--polling/--no-polling', default=True)
def process_reports(debug, workspace, polling):
    try:
        from requests import ConnectionError
    except ImportError:
        print('Python requests was not found. Please install it with: pip install requests')
        sys.exit(1)
    try:
        from sqlalchemy.exc import OperationalError
    except ImportError:
        print('SQLAlchemy was not found please install it with: pip install sqlalchemy')
        sys.exit(1)
    setUpLogger(debug)
    configuration = _conf()
    url = '{0}/_api/v2/info'.format(configuration.getServerURI() if FARADAY_UP else SERVER_URL)
    with app.app_context():
        try:
            check_faraday_server(url)
            import_external_reports(workspace, polling)
        except OperationalError as ex:
            print('{0}'.format(ex))
            print('Please verify database is running or configuration on server.ini!')
        except ConnectionError:
            print('Can\'t connect to {0}. Please check if the server is running.'.format(url))


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
        ImportCouchDB().run()

@click.command()
def import_from_couchdb():
    with app.app_context():
        ImportCouchDB().run()

@click.command()
def database_schema():
    DatabaseSchema().run()

@click.command()
def sql_shell():
    try:
        from pgcli.main import PGCli
    except ImportError:
        print('PGCli was not found, please install it with: pip install pgcli')
        sys.exit(1)
    conn_string = server.config.database.connection_string.strip("'")

    pgcli = PGCli()
    pgcli.connect_uri(conn_string)
    pgcli.run_cli()


@click.command()
def status_check():
    full_status_check()


def validate_user_unique_field(ctx, param, value):
    with app.app_context():
        if User.query.filter_by(**{param.name: value}).count():
            raise click.ClickException("User already exists")
    return value


def validate_email(ctx, param, value):
    if not re.match(r'[^@]+@[^@]+\.[^@]+', value):
        raise click.BadParameter('Invalid email')

    # Also validate that the email doesn't exist in the database
    return validate_user_unique_field(ctx, param, value)


@click.command()
@click.option('--username', prompt=True, callback=validate_user_unique_field)
@click.option('--email', prompt=True, callback=validate_email)
@click.option('--password', prompt=True, hide_input=True,
              confirmation_prompt=True)
def createsuperuser(username, email, password):
    with app.app_context():
        if db.session.query(User).filter_by(active=True).count() > 0:
            print("Can't create more users. Please contact support")
            sys.exit(1)
        app.user_datastore.create_user(username=username,
                                       email=email,
                                       password=password,
                                       role='admin',
                                       is_ldap=False)   
        db.session.commit()
        click.echo(click.style(
            'User {} created successfully!'.format(username),
            fg='green', bold=True))


cli.add_command(process_reports)
cli.add_command(show_urls)
cli.add_command(faraday_schema_display)
cli.add_command(initdb)
cli.add_command(import_from_couchdb)
cli.add_command(database_schema)
cli.add_command(createsuperuser)
cli.add_command(sql_shell)
cli.add_command(status_check)


if __name__ == '__main__':
    cli()

