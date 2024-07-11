#!/usr/bin/env python
"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import os
import re
import sys
import platform
import logging

import click
import requests
import alembic.command
from flask_security.utils import hash_password
from pgcli.main import PGCli
from urllib.parse import urlparse
from alembic.config import Config
from sqlalchemy.exc import ProgrammingError, OperationalError

import faraday.server.config
from faraday.server.app import get_app
from faraday.server.commands.sync_hosts_stats import _sync_hosts_stats
from faraday.server.commands.ingestelk import _ingest
from faraday.server.config import FARADAY_BASE
from faraday.server.commands.initdb import InitDB
from faraday.server.commands.faraday_schema_display import DatabaseSchema
from faraday.server.commands.app_urls import show_all_urls
from faraday.server.commands.app_urls import openapi_format
from faraday.server.commands import change_password as change_pass
from faraday.server.commands.custom_fields import add_custom_field_main, delete_custom_field_main
from faraday.server.commands import change_username
from faraday.server.commands import nginx_config
from faraday.server.commands import import_vulnerability_template
from faraday.server.commands import manage_settings
from faraday.server.models import db, User, LOCAL_TYPE
from faraday_plugins.plugins.manager import PluginsManager
from faraday.server.commands.move_references import _move_references


CONTEXT_SETTINGS = {'help_option_names': ['-h', '--help']}

os.environ['FARADAY_MANAGE_RUNNING'] = "1"
# If is linux and its installed with deb or rpm, it must run with a user in the faraday group
if platform.system() == "Linux":
    import grp
    from getpass import getuser

    try:
        FARADAY_GROUP = "faraday"
        faraday_group = grp.getgrnam(FARADAY_GROUP)
        # The current user may be different from the logged user
        current_user = getuser()
        if current_user != 'root' and faraday_group.gr_gid not in os.getgroups():
            print(f"\n\nUser ({os.getlogin()}) must be in the '{FARADAY_GROUP}' group.")
            print("After adding the user to the group, please logout and login again.")
            sys.exit(1)
    except KeyError:
        pass

app = get_app(register_extensions_flag=False)


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


def check_faraday_server(url):
    return requests.get(url, timeout=10)


@click.command(help="Show all URLs in Faraday Server API")
def show_urls():
    with app.app_context():
        show_all_urls()


@click.command(help="Creates Faraday Swagger config file")
@click.option('--server', prompt=True, default="http://localhost:5985")
@click.option('--modify_default', default=False)
def openapi_swagger(server, modify_default):
    with app.app_context():
        openapi_format(server=server, modify_default=modify_default)


@click.command(help="Import Vulnerability templates")
@click.option('--language', required=False, default='en')
@click.option('--list-languages', is_flag=True)
def import_vulnerability_templates(language, list_languages):
    with app.app_context():
        import_vulnerability_template.run(language, list_languages)


@click.command(help="Create Faraday DB in Postgresql, also tables and indexes")
@click.option(
    '--choose-password', is_flag=True, default=False,
    help=('Instead of using a random password for the user "faraday", '
          'ask for the desired one')
)
@click.option(
    '--password', type=str,
    help=('Instead of using a random password for the user "faraday", '
          'use the one provided')
)
def initdb(choose_password, password):
    with app.app_context():
        InitDB().run(choose_password=choose_password, faraday_user_password=password)


@click.command(help="Create a PNG image with Faraday model object")
def database_schema():
    DatabaseSchema().run()


@click.command(help="Open a SQL Shell connected to postgresql 'Faraday DB'")
def sql_shell():
    conn_string = faraday.server.config.database.connection_string.strip("'")
    conn_string = urlparse(conn_string)
    parsed_conn_string = (f"user={conn_string.username} password={conn_string.password} host={conn_string.hostname} "
                          f"dbname={conn_string.path[1:]}")
    pgcli = PGCli()
    pgcli.connect_uri(parsed_conn_string)
    pgcli.run_cli()


@click.command(help="Changes the password of a user")
@click.option('--username', required=True, prompt=True)
@click.option('--password', required=True, prompt=True, confirmation_prompt=True, hide_input=True)
def change_password(username, password):
    try:
        with app.app_context():
            change_pass.changes_password(username, password)
    except ProgrammingError:
        print('\n\nMissing migrations, please execute: \n\nfaraday-manage migrate')
        sys.exit(1)


def validate_user_unique_field(ctx, param, value):
    with app.app_context():
        try:
            if User.query.filter_by(**{param.name: value}).count():
                raise click.ClickException("User already exists")
        except OperationalError:
            logger = logging.getLogger(__name__)
            logger.error(
                'Could not connect to PostgreSQL. Please check: '
                 'if database is running or if the configuration settings are correct.'
            )
            sys.exit(1)

    return value


def validate_email(ctx, param, value):
    if not re.match(r'[^@]+@[^@]+\.[^@]+', value):
        raise click.BadParameter('Invalid email')

    # Also validate that the email doesn't exist in the database
    return validate_user_unique_field(ctx, param, value)


@click.command(help="List Available Plugins")
def list_plugins():
    plugins_manager = PluginsManager()
    for _, plugin in plugins_manager.get_plugins():
        click.echo(f"{plugin.id}")


@click.command(help="Create ADMIN user for Faraday application")
@click.option('--username', prompt=True, callback=validate_user_unique_field)
@click.option('--email', prompt=True, callback=validate_email)
@click.option('--password', prompt=True, hide_input=True,
              confirmation_prompt=True)
def create_superuser(username, email, password):
    with app.app_context():
        if db.session.query(User).filter_by(active=True).count() > 0:
            print(
                "Can't create more users. The community edition only allows one user. "
                "Please contact support for further information.")
            sys.exit(1)

        app.user_datastore.create_user(username=username,
                                       email=email,
                                       password=hash_password(password),
                                       roles=['admin'],
                                       user_type=LOCAL_TYPE)
        db.session.commit()
        click.echo(click.style(
            f'User {username} created successfully!',
            fg='green', bold=True))


@click.command(help="Create database tables. Requires a functional "
                    "PostgreSQL database configured in the server.ini")
def create_tables():
    with app.app_context():
        # Ugly hack to create tables and also setting alembic revision
        conn_string = faraday.server.config.database.connection_string
        if not conn_string:
            logger = logging.getLogger(__name__)
            logger.error(
                'No database configuration found. Please check: '
                 'if the database is running or if the configuration settings are correct. '
                 'For first time installations execute: faraday-manage initdb'
            )
            sys.exit(1)
        InitDB()._create_tables(conn_string)
        click.echo(click.style(
            'Tables created successfully!',
            fg='green', bold=True))


@click.command(
    context_settings={"ignore_unknown_options": True},
    help='Migrates database schema. If the target revision '
         'is not specified, use "head" when upgrading and "-1" when '
         'downgrading')
@click.option(
    '--downgrade',
    help="Perform a downgrade migration instead of an upgrade one",
    is_flag=True)
@click.argument(
    'revision',
    required=False,
)
def migrate(downgrade, revision):
    with app.app_context():
        try:
            revision = revision or ("-1" if downgrade else "head")
            config = Config(FARADAY_BASE / "alembic.ini")
            os.chdir(FARADAY_BASE)
            if downgrade:
                alembic.command.downgrade(config, revision)
            else:
                alembic.command.upgrade(config, revision)
            # TODO Return to prev dir
        except OperationalError as e:
            logger = logging.getLogger(__name__)
            logger.error("Migration Error: %s", e)
            logger.exception(e)
            print('Please verify your configuration on server.ini or the hba configuration!')
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error("Migration Error: %s", e)
            print('Migration failed!', e)
            sys.exit(1)


@click.command(help='Custom field wizard')
def add_custom_field():
    with app.app_context():
        add_custom_field_main()


@click.command(help='Custom field delete wizard')
def delete_custom_field():
    with app.app_context():
        delete_custom_field_main()


@click.command(help="Change username")
@click.option('--current_username', required=True, prompt=True)
@click.option('--new_username', required=True, prompt=True)
def rename_user(current_username, new_username):
    if (current_username == new_username):
        print("\nERROR: Usernames must be different.")
        sys.exit(1)
    else:
        with app.app_context():
            change_username.change_username(current_username, new_username)


@click.command(help="Generate nginx config")
@click.option('--fqdn', prompt='Server FQDN', help='The FQDN of your faraday server', type=str, show_default=True)
@click.option('--port', prompt='Faraday port', help='Faraday listening port', type=int, default=5985)
@click.option('--ws-port', prompt='Faraday Websocket port', help='Faraday websocket listening port', type=int,
              default=9000, show_default=True)
@click.option('--ssl-certificate', prompt='SSL Certificate Path', help='SSL Certificate Path',
              type=click.Path(exists=True))
@click.option('--ssl-key', prompt='SSL Key Path', help='SSL Key Path', type=click.Path(exists=True))
@click.option('--multitenant-url', help='URL for multitenant config', type=str)
def generate_nginx_config(fqdn, port, ws_port, ssl_certificate, ssl_key, multitenant_url):
    nginx_config.generate_nginx_config(fqdn, port, ws_port, ssl_certificate, ssl_key, multitenant_url)


@click.command(help="Manage settings")
@click.option('-a', '--action', type=click.Choice(['show', 'update', 'list', 'clear'], case_sensitive=False),
              default='list', show_default=True, help="Action")
@click.option('--data', type=str, required=False, callback=manage_settings.settings_format_validation,
              help="Settings config in json")
@click.argument('name', required=False)
def settings(action, data, name):
    with app.app_context():
        manage_settings.manage(action.lower(), data, name)


@click.command(help="Move references from deprecated model to new one")
@click.option('-a', '--all-workspaces', type=bool, help="Move references of all workspaces", default=False)
@click.option('-w', '--workspace-name', help="Specify workspace name")
def move_references(all_workspaces, workspace_name):
    app = get_app(register_extensions_flag=False)
    with app.app_context():
        _move_references(all_workspaces=all_workspaces, workspace_name=workspace_name)


@click.command(help="Import vulnerabilities from one or all workspaces into Elasticsearch. ")
@click.option('--all-workspaces/--no-all-workspaces', default=False,
              help="Imports vulnerabilities from all workspaces. This option takes precedence over '--workspace-name'. "
                   "By default, it is set to not import from all workspaces.")
@click.option('-w', '--workspace-name', help="Imports vulnerabilities from the specified workspace name. "
                                             "This option has no effect if '--all-workspaces' is already specified.")
@click.option('-f', '--from-id', help="Specify the starting vulnerability id for import.")
@click.option('-t', '--to-id', help="Specify the ending vulnerability id for import.")
@click.option('-r', '--rename-workspace-as', help="Rename workspace in Elasticsearch with the specified new name.")
@click.option('-x', '--add-extra-vulnerability-tags', help="Additional tags to add to vulnerabilities.")
@click.option('-i', '--elk-index-name', default='faraday', help="Name of the Elasticsearch index. Default is 'faraday'.")
@click.option('-d', '--from-update-date', help="Import vulnerabilities from the specified update date.")
@click.option('-c', '--test-connection', is_flag=True, default=False,
              help="Just test connection with elastic and exit.")
def ingest(all_workspaces,
           workspace_name,
           from_id,
           to_id,
           rename_workspace_as,
           add_extra_vulnerability_tags,
           elk_index_name,
           from_update_date,
           test_connection):
    with get_app().app_context():
        _ingest(all_workspaces=all_workspaces,
                workspace_name=workspace_name,
                from_id=from_id,
                to_id=to_id,
                rename_as=rename_workspace_as,
                extra_vuln_tags=add_extra_vulnerability_tags,
                index_name=elk_index_name,
                from_update=from_update_date,
                test_connection=test_connection
                )


@click.command(help="Synchronize vulnerability severity stats in asset")
@click.option('-a', '--async-mode', type=bool, help="Update stats asynchronously", default=False)
def sync_hosts_stats(async_mode):
    app = get_app()
    with app.app_context():
        _sync_hosts_stats(async_mode)


cli.add_command(show_urls)
cli.add_command(initdb)
cli.add_command(database_schema)
cli.add_command(create_superuser)
cli.add_command(sql_shell)
cli.add_command(create_tables)
cli.add_command(change_password)
cli.add_command(migrate)
cli.add_command(add_custom_field)
cli.add_command(delete_custom_field)
cli.add_command(list_plugins)
cli.add_command(rename_user)
cli.add_command(openapi_swagger)
cli.add_command(generate_nginx_config)
cli.add_command(import_vulnerability_templates)
cli.add_command(settings)
cli.add_command(move_references)
cli.add_command(sync_hosts_stats)
cli.add_command(ingest)


if __name__ == '__main__':
    cli()
