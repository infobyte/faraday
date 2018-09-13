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
from server.commands import status_check as status_check_functions
from server.commands import change_password as change_pass
from server.models import db, User
from server.importer import ImportCouchDB

from server.web import app
from utils.logs import setUpLogger

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


def check_faraday_server(url):
    return requests.get(url)


@click.command(help="Enable importation of plugins reports in ~/.faraday folder")
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


@click.command(help="Show all URLs in Faraday Server API")
def show_urls():
    show_all_urls()

@click.command(help="Create Faraday DB in Postgresql, also tables and indexes")
@click.option(
        '--choose-password', is_flag=True, default=False,
        help=('Instead of using a random password for the user "faraday", '
              'ask for the desired one')
        )
def initdb(choose_password):
    with app.app_context():
        InitDB().run(choose_password=choose_password)
        couchdb_config_present = server.config.couchdb
        if couchdb_config_present and couchdb_config_present.user and couchdb_config_present.password:
            print('Importing data from CouchDB, please wait...')
            ImportCouchDB().run()
            print('All users from CouchDB were imported. You can login with your old username/password to faraday now.')

@click.command(help="Import all your data from Couchdb Faraday databases")
def import_from_couchdb():
    with app.app_context():
        ImportCouchDB().run()

@click.command(help="Create a PNG image with Faraday model object")
def database_schema():
    DatabaseSchema().run()

@click.command(help="Open a SQL Shell connected to postgresql 'Faraday DB'")
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


@click.command(help='Checks configuration and faraday status.')
@click.option('--check_postgresql', default=False, is_flag=True)
@click.option('--check_faraday', default=False, is_flag=True)
@click.option('--check_dependencies', default=False, is_flag=True)
@click.option('--check_config', default=False, is_flag=True)
def status_check(check_postgresql, check_faraday, check_dependencies, check_config):

    selected = False
    exit_code = 0
    if check_postgresql:
        # exit_code was created for Faraday automation-testing purposes
        exit_code = status_check_functions.print_postgresql_status()
        status_check_functions.print_postgresql_locks_status()
        selected = True

    if check_faraday:
        status_check_functions.print_faraday_status()
        selected = True

    if check_dependencies:
        status_check_functions.print_depencencies_status()
        selected = True

    if check_config:
        status_check_functions.print_config_status()
        selected = True

    if not selected:
        status_check_functions.full_status_check()

    sys.exit(exit_code)

@click.command(help="Changes the password of a user")
def change_password():
    username = raw_input("Enter the Name of the User: ")
    password = raw_input("Enter the new password: ")
    if password is None or password == "":
        print "Invalid password"
        exit
    change_pass.changes_password(username, password)

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


@click.command(help="Create ADMIN user for Faraday application")
@click.option('--username', prompt=True, callback=validate_user_unique_field)
@click.option('--email', prompt=True, callback=validate_email)
@click.option('--password', prompt=True, hide_input=True,
              confirmation_prompt=True)
def createsuperuser(username, email, password):
    with app.app_context():
        if db.session.query(User).filter_by(active=True).count() > 0:
            print("Can't create more users. The comumunity edition only allows one user. Please contact support for further information.")
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


@click.command(help="Create database tables. Requires a functional "
               "PostgreSQL database configured in the server.ini")
def create_tables():
    with app.app_context():
        # Ugly hack to create tables and also setting alembic revision
        import server.config
        conn_string = server.config.database.connection_string
        from server.commands.initdb import InitDB
        InitDB()._create_tables(conn_string)
        click.echo(click.style(
            'Tables created successfully!',
            fg='green', bold=True))


cli.add_command(process_reports)
cli.add_command(show_urls)
cli.add_command(initdb)
cli.add_command(import_from_couchdb)
cli.add_command(database_schema)
cli.add_command(createsuperuser)
cli.add_command(sql_shell)
cli.add_command(status_check)
cli.add_command(create_tables)
cli.add_command(change_password)


if __name__ == '__main__':
    cli()
