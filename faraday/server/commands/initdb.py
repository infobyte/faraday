"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from builtins import input

import getpass
import string
import uuid
import os
import sys
import click
import psycopg2
from alembic.config import Config
from alembic import command
from random import SystemRandom
from tempfile import TemporaryFile
from subprocess import Popen  # nosec

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.sql import text

from faraday.server.utils.database import is_unique_constraint_violation

from configparser import ConfigParser, NoSectionError

from flask import current_app
from flask_security.utils import hash_password

from colorama import init
from colorama import Fore
from sqlalchemy.exc import OperationalError, ProgrammingError

import faraday.server.config
from faraday.server.config import CONST_FARADAY_HOME_PATH
from faraday.server.config import LOCAL_CONFIG_FILE, FARADAY_BASE

init()


class InitDB():

    def _check_current_config(self, config):
        try:
            config.get('database', 'connection_string')
            reconfigure = None
            while not reconfigure:
                reconfigure = input(
                    f'Database section {Fore.YELLOW} already found{Fore.WHITE}. Do you want to reconfigure database? (yes/no) ')
                if reconfigure.lower() == 'no':
                    return False
                elif reconfigure.lower() == 'yes':
                    continue
                else:
                    reconfigure = None
        except NoSectionError:
            config.add_section('database')

        return True

    def run(self, choose_password, faraday_user_password):
        """
             Main entry point that executes these steps:
                 * creates role in database.
                 * creates database.
                 * save new configuration on server.ini.
                 * creates tables.
        """
        try:
            config = ConfigParser()
            config.read(LOCAL_CONFIG_FILE)
            if not self._check_current_config(config):
                return
            faraday_path_conf = CONST_FARADAY_HOME_PATH
            # we use psql_log_filename for historical saving. we will ask faraday users this file.
            # current_psql_output is for checking psql command already known errors for each execution.
            psql_log_filename = faraday_path_conf / 'logs' / 'psql_log.log'
            current_psql_output = TemporaryFile()
            with open(psql_log_filename, 'ab+') as psql_log_file:
                hostname = 'localhost'
                username, password, process_status = self._configure_new_postgres_user(current_psql_output)
                current_psql_output.seek(0)
                psql_output = current_psql_output.read()
                # persist log in the faraday log psql_log.log
                psql_log_file.write(psql_output)
                self._check_psql_output(current_psql_output, process_status)

                if hostname.lower() in ['localhost', '127.0.0.1']:
                    database_name = os.environ.get("FARADAY_DATABASE_NAME", "faraday")
                    current_psql_output = TemporaryFile()
                    database_name, process_status = self._create_database(database_name, username, current_psql_output)
                    current_psql_output.seek(0)
                    self._check_psql_output(current_psql_output, process_status)

            current_psql_output.close()
            conn_string = self._save_config(config, username, password, database_name, hostname)
            self._create_tables(conn_string)
            self._create_admin_user(conn_string, choose_password, faraday_user_password)
        except KeyboardInterrupt:
            current_psql_output.close()
            print('User cancelled.')
            sys.exit(1)

    def _create_roles(self, conn_string):
        engine = create_engine(conn_string)
        try:
            statement = text(
                "INSERT INTO faraday_role(name) VALUES ('admin'),('pentester'),('client'),('asset_owner');"
            )
            connection = engine.connect()
            connection.execute(statement)
        except sqlalchemy.exc.IntegrityError as ex:
            if is_unique_constraint_violation(ex):
                # when re using database user could be created previously
                print(
                    "{yellow}WARNING{white}: Faraday administrator user already exists.".format(
                        yellow=Fore.YELLOW, white=Fore.WHITE))
            else:
                print(
                    "{yellow}WARNING{white}: Can't create administrator user.".format(
                        yellow=Fore.YELLOW, white=Fore.WHITE))
                raise

    def _create_initial_notifications_config(self):
        from faraday.server.models import (db,  # pylint:disable=import-outside-toplevel
                                           Role,  # pylint:disable=import-outside-toplevel
                                           NotificationSubscription,  # pylint:disable=import-outside-toplevel
                                           NotificationSubscriptionWebSocketConfig,  # pylint:disable=import-outside-toplevel
                                           EventType,  # pylint:disable=import-outside-toplevel
                                           User,  # pylint:disable=import-outside-toplevel
                                           ObjectType)  # pylint:disable=import-outside-toplevel

        admin = User.ADMIN_ROLE
        pentester = User.PENTESTER_ROLE
        asset_owner = User.ASSET_OWNER_ROLE
        client = User.CLIENT_ROLE

        default_initial_notifications_config = [
            # Workspace
            {'roles': [admin], 'event_types': ['new_workspace', 'update_workspace', 'delete_workspace']},
            # Users
            {'roles': [admin], 'event_types': ['new_user', 'update_user', 'delete_user']},
            # Agents
            {'roles': [admin, pentester], 'event_types': ['new_agent', 'update_agent', 'delete_agent']},
            # Reports
            {'roles': [admin, pentester, asset_owner],
             'event_types': ['new_executivereport', 'update_executivereport', 'delete_executivereport']},
            # Agent execution
            {'roles': [admin, pentester, asset_owner], 'event_types': ['new_agentexecution']},
            # Commands
            {'roles': [admin, pentester, asset_owner], 'event_types': ['new_command']},
            # Vulnerability
            {'roles': [admin, pentester, asset_owner, client],
             'event_types': ['new_vulnerability', 'update_vulnerability', 'delete_vulnerability']},
            # Vulnerability Web
            {'roles': [admin, pentester, asset_owner, client],
             'event_types': ['new_vulnerabilityweb', 'update_vulnerabilityweb', 'delete_vulnerabilityweb']},
            # Comments
            {'roles': [admin, pentester, asset_owner, client], 'event_types': ['new_comment']},
        ]

        event_types = [('new_workspace', False),
                       ('new_agent', True),
                       ('new_user', False),
                       ('new_agentexecution', True),
                       ('new_executivereport', True),
                       ('new_vulnerability', False),
                       ('new_command', True),
                       ('new_comment', False),
                       ('update_workspace', False),
                       ('update_agent', False),
                       ('update_user', False),
                       ('update_executivereport', True),
                       ('update_vulnerability', False),
                       ('delete_workspace', False),
                       ('delete_agent', False),
                       ('delete_user', False),
                       ('delete_executivereport', False),
                       ('delete_vulnerability', False),
                       ('new_vulnerabilityweb', False),
                       ('update_vulnerabilityweb', False),
                       ('delete_vulnerabilityweb', False)]

        for event_type in event_types:
            event_type_obj = EventType(name=event_type[0], async_event=event_type[1])
            db.session.add(event_type_obj)

        object_types = ['vulnerability',
                        'vulnerabilityweb',
                        'host',
                        'credential',
                        'service',
                        'source_code',
                        'comment',
                        'executivereport',
                        'workspace',
                        'task',
                        'agent',
                        'agentexecution',
                        'command',
                        'user']

        for object_type in object_types:
            obj = ObjectType(name=object_type)
            db.session.add(obj)
            db.session.commit()

        for config in default_initial_notifications_config:
            for event_type in config['event_types']:
                allowed_roles_objs = Role.query.filter(Role.name.in_(config['roles'])).all()
                event_type_obj = EventType.query.filter(EventType.name == event_type).first()
                n = NotificationSubscription(event_type=event_type_obj, allowed_roles=allowed_roles_objs)
                db.session.add(n)
                db.session.commit()
                ns = NotificationSubscriptionWebSocketConfig(subscription=n, active=True, role_level=True)
                db.session.add(ns)
                db.session.commit()

    def _create_admin_user(self, conn_string, choose_password, faraday_user_password):
        engine = create_engine(conn_string)
        # TODO change the random_password variable name, it is not always
        # random anymore
        if choose_password:
            user_password = click.prompt(
                'Enter the desired password for the "faraday" user',
                confirmation_prompt=True,
                hide_input=True
            )
        else:
            if faraday_user_password:
                user_password = faraday_user_password
            else:
                user_password = self.generate_random_pw(12)
        already_created = False
        fs_uniquifier = str(uuid.uuid4())
        try:

            statement = text("""
                INSERT INTO faraday_user (
                            username, name, password,
                            is_ldap, active, last_login_ip,
                            current_login_ip, state_otp, fs_uniquifier
                        ) VALUES (
                            'faraday', 'Administrator', :password,
                            false, true, '127.0.0.1',
                            '127.0.0.1', 'disabled', :fs_uniquifier
                        )
            """)
            params = {
                'password': hash_password(user_password),
                'fs_uniquifier': fs_uniquifier
            }
            connection = engine.connect()
            connection.execute(statement, **params)
            result = connection.execute(text("""SELECT id, username FROM faraday_user"""))
            user_id = list(user_tuple[0] for user_tuple in result if user_tuple[1] == "faraday")[0]
            result = connection.execute(text("""SELECT id, name FROM faraday_role"""))
            role_id = list(role_tuple[0] for role_tuple in result if role_tuple[1] == "admin")[0]
            params = {
                "user_id": user_id,
                "role_id": role_id
            }
            connection.execute(text("INSERT INTO roles_users(user_id, role_id) VALUES (:user_id, :role_id)"), **params)
        except sqlalchemy.exc.IntegrityError as ex:
            if is_unique_constraint_violation(ex):
                # when re using database user could be created previously
                already_created = True
                print(
                    "{yellow}WARNING{white}: Faraday administrator user already exists.".format(
                        yellow=Fore.YELLOW, white=Fore.WHITE))
            else:
                print(
                    "{yellow}WARNING{white}: Can't create administrator user.".format(
                        yellow=Fore.YELLOW, white=Fore.WHITE))
                raise
        if not already_created:
            print("Admin user created with \n\n{red}username: {white}faraday \n"
                  "{red}password:{white} {"
                  "user_password} \n".format(user_password=user_password,
                                             white=Fore.WHITE, red=Fore.RED))

    def _configure_existing_postgres_user(self):
        username = input('Please enter the postgresql username: ')
        password = getpass.getpass('Please enter the postgresql password: ')

        return username, password

    def _check_psql_output(self, current_psql_output_file, process_status):
        current_psql_output_file.seek(0)
        psql_output = current_psql_output_file.read().decode('utf-8')
        if 'unknown user: postgres' in psql_output:
            print(f'ERROR: Postgres user not found. Did you install package {Fore.BLUE}postgresql{Fore.WHITE}?')
        elif 'could not connect to server' in psql_output:
            print(
                f'ERROR: {Fore.RED}PostgreSQL service{Fore.WHITE} is not running. Please verify that it is running in port 5432 before executing setup script.')
        elif process_status > 0:
            current_psql_output_file.seek(0)
            print('ERROR: ' + psql_output)

        if process_status != 0:
            current_psql_output_file.close()  # delete temp file
            sys.exit(process_status)

    def generate_random_pw(self, pwlen):
        rng = SystemRandom()
        return "".join([rng.choice(string.ascii_letters + string.digits) for _ in range(pwlen)])

    def _configure_new_postgres_user(self, psql_log_file):
        """
            This step will create the role on the database.
            we return username and password and those values will be saved in the config file.
        """
        print(
            'This script will {blue} create a new postgres user {white} and {blue} save faraday-server settings {white}(server.ini). '.format(
                blue=Fore.BLUE, white=Fore.WHITE))
        username = os.environ.get("FARADAY_DATABASE_USER", 'faraday_postgresql')
        postgres_command = ['sudo', '-u', 'postgres', 'psql']
        if sys.platform == 'darwin':
            print(f'{Fore.BLUE}MAC OS detected{Fore.WHITE}')
            postgres_command = ['psql', 'postgres']
        password = self.generate_random_pw(25)
        command = postgres_command + ['-c', 'CREATE ROLE {0} WITH LOGIN PASSWORD \'{1}\';'.format(username, password)]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file)  # nosec
        p.wait()
        psql_log_file.seek(0)
        output = psql_log_file.read()
        if isinstance(output, bytes):
            output = output.decode('utf-8')
        already_exists_error = f'role "{username}" already exists'
        return_code = p.returncode
        if already_exists_error in output:
            print(f"{Fore.YELLOW}WARNING{Fore.WHITE}: Role {username} already exists, skipping creation ")

            try:
                if not getattr(faraday.server.config, 'database', None):
                    print(
                        'Manual configuration? \n faraday_postgresql was found in PostgreSQL, but no connection string was found in server.ini. ')
                    print(
                        'Please configure [database] section with correct postgresql string. Ex. postgresql+psycopg2://faraday_postgresql:PASSWORD@localhost/faraday')
                    sys.exit(1)
                try:
                    password = faraday.server.config.database.connection_string.split(':')[2].split('@')[0]
                except AttributeError:
                    print('Could not find connection string.')
                    print(
                        'Please configure [database] section with correct postgresql string. Ex. postgresql+psycopg2://faraday_postgresql:PASSWORD@localhost/faraday')
                    sys.exit(1)
                connection = psycopg2.connect(dbname='postgres',
                                              user=username,
                                              password=password)
                cur = connection.cursor()
                cur.execute('SELECT * FROM pg_catalog.pg_tables;')
                cur.fetchall()
                connection.commit()
                connection.close()
            except psycopg2.Error as e:
                if 'authentication failed' in str(e):
                    print('{red}ERROR{white}: User {username} already '
                          'exists'.format(white=Fore.WHITE,
                                          red=Fore.RED,
                                          username=username))
                    sys.exit(1)
                else:
                    raise
            return_code = 0
        return username, password, return_code

    def _create_database(self, database_name, username, psql_log_file):
        """
             This step uses the createdb command to add a new database.
        """
        postgres_command = ['sudo', '-u', 'postgres']
        if sys.platform == 'darwin':
            postgres_command = []

        print(f'Creating database {database_name}')
        command = postgres_command + ['createdb', '-E', 'utf8', '-O', username, database_name]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file, cwd='/tmp')  # nosec
        p.wait()
        return_code = p.returncode
        psql_log_file.seek(0)
        output = psql_log_file.read().decode('utf-8')
        already_exists_error = f'database creation failed: ERROR:  database "{database_name}" already exists'
        if already_exists_error in output:
            print(f'{Fore.YELLOW}WARNING{Fore.WHITE}: Database already exists.')
            return_code = 0
        return database_name, return_code

    def _save_config(self, config, username, password, database_name, hostname):
        """
             This step saves database configuration to server.ini
        """
        print(f'Saving database credentials file in {LOCAL_CONFIG_FILE}')

        conn_string = 'postgresql+psycopg2://{username}:{password}@{server}/{database_name}'.format(
            username=username,
            password=password,
            server=hostname,
            database_name=database_name
        )
        config.set('database', 'connection_string', conn_string)
        with open(LOCAL_CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        return conn_string

    def _create_tables(self, conn_string):
        print('Creating tables')
        from faraday.server.models import db  # pylint:disable=import-outside-toplevel
        current_app.config['SQLALCHEMY_DATABASE_URI'] = conn_string

        # Check if the alembic_version exists
        # Taken from https://stackoverflow.com/a/24089729
        (result,) = list(db.session.execute("select to_regclass('alembic_version')"))
        exists = result[0] is not None

        if exists:
            print("Faraday tables already exist in the database. No tables will "
                  "be created. If you want to ugprade the schema to the latest "
                  "version, you should run \"faraday-manage migrate\".")
            return

        try:
            db.create_all()
        except OperationalError as ex:
            if 'could not connect to server' in str(ex):
                print(
                    f'ERROR: {Fore.RED}PostgreSQL service{Fore.WHITE} is not running. Please verify that it is running in port 5432 before executing setup script.')
                sys.exit(1)
            elif 'password authentication failed' in str(ex):
                print('ERROR: ')
                sys.exit(1)
            else:
                raise
        except ProgrammingError as ex:
            print(ex)
            print('Please check postgres user permissions.')
            sys.exit(1)
        except ImportError as ex:
            if 'psycopg2' in str(ex):
                print(
                    f'ERROR: Missing python depency {Fore.RED}psycopg2{Fore.WHITE}. Please install it with {Fore.BLUE}pip install psycopg2')
                sys.exit(1)
            else:
                raise
        else:
            alembic_cfg = Config(FARADAY_BASE / 'alembic.ini')
            os.chdir(FARADAY_BASE)
            command.stamp(alembic_cfg, "head")
            # TODO ADD RETURN TO PREV DIR
        self._create_roles(conn_string)
        self._create_initial_notifications_config()
