#!/usr/bin/env python
"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import getpass
import shutil
import string

import os
import sys
import click
import psycopg2
from random import SystemRandom
from tempfile import TemporaryFile
from subprocess import Popen, PIPE

import sqlalchemy
from sqlalchemy import create_engine

from config.configuration import Configuration
from faraday import (
    FARADAY_USER_CONFIG_XML,
    FARADAY_BASE_CONFIG_XML,
    FARADAY_BASE
)

try:
    # py2.7
    from configparser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    # py3
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError

from flask import current_app
from colorama import init
from colorama import Fore
from sqlalchemy.exc import OperationalError, ProgrammingError

import server.config
from config.globals import CONST_FARADAY_HOME_PATH
from server.config import LOCAL_CONFIG_FILE
from paramiko import SSHClient, AutoAddPolicy

init()


class InitDB:

    def __init__(self):
        self.configure_db = False
        self.host_local = False

    def _check_current_config(self, config):
        try:
            config.get('database', 'connection_string')
            while not self.configure_db:
                rsp = raw_input('Database section {yellow} already found{white}. Do you want to reconfigure database? (yes/no) '.format(yellow=Fore.YELLOW, white=Fore.WHITE))
                if rsp.lower() == 'yes':
                    self.configure_db = True
        except NoSectionError:
            print('Database section not found. Configuring ...')
            config.add_section('database')
            self.configure_db = True
        finally:
            return

    def run(self, choose_password):
        """
             Main entry point that executes these steps:
                 * creates role in database.
                 * creates database.
                 * save new configuration on server.ini.
                 * creates tables.
        """
        current_psql_output = TemporaryFile()
        database_name = 'faraday'
        try:
            config = ConfigParser()
            config.read(LOCAL_CONFIG_FILE)
            self._check_current_config(config)
            if not self.configure_db:
                return
            faraday_path_conf = os.path.expanduser(CONST_FARADAY_HOME_PATH)
            # we use psql_log_filename for historical saving. we will ask faraday users this file.
            # current_psql_output is for checking psql command already known errors for each execution.
            psql_log_filename = os.path.join(faraday_path_conf, 'logs', 'psql_log.log')
            with open(psql_log_filename, 'a+') as psql_log_file:
                hostname = raw_input('Please enter your postgresql server address and port (Default: 127.0.0.1:5432): ') or "127.0.0.1:5432"
                if hostname.startswith("127.0.0.1"):
                    self.host_local = True
                username, password, process_status = self._configure_new_postgres_user(hostname, current_psql_output)
                current_psql_output.seek(0)
                psql_output = current_psql_output.read()
                # persist log in the faraday log psql_log.log
                psql_log_file.write(psql_output)
                self._check_psql_output(current_psql_output, process_status)
                database_name, process_status = self._create_database(hostname, database_name, username, current_psql_output)

            conn_string = self._save_config(config, username, password, database_name, hostname)
            self._create_tables(conn_string)
            couchdb_config_present = server.config.couchdb
            if not (couchdb_config_present and couchdb_config_present.user and couchdb_config_present.password):
                self._create_admin_user(conn_string, choose_password)
            else:
                print('Skipping new admin creation since couchdb configuration was found.')
        except KeyboardInterrupt:
            print('User cancelled.')
            sys.exit(1)
        finally:
            current_psql_output.close()

    def _create_admin_user(self, conn_string, choose_password):
        engine = create_engine(conn_string)
        # TODO change the random_password variable name, it is not always
        # random anymore
        if choose_password:
            random_password = click.prompt(
                'Enter the desired password for the "faraday" user',
                confirmation_prompt=True,
                hide_input=True
            )
        else:
            random_password = self.generate_random_pw(12)
        already_created = False
        try:
            engine.execute("INSERT INTO \"faraday_user\" (username, name, password, "
                           "is_ldap, active, last_login_ip, current_login_ip, role) VALUES ('faraday', 'Administrator', "
                           "'{0}', false, true, '127.0.0.1', '127.0.0.1', 'admin');".format(random_password))
        except sqlalchemy.exc.IntegrityError:
            # when re using database user could be created previusly
            already_created = True
            print("{yellow}WARNING{white}: Faraday administrator user already exists.".format(yellow=Fore.YELLOW, white=Fore.WHITE))
        if not already_created:
            if not os.path.isfile(FARADAY_USER_CONFIG_XML):
                shutil.copy(FARADAY_BASE_CONFIG_XML, FARADAY_USER_CONFIG_XML)
            self._save_user_xml(random_password)
            print("Admin user created with \n\n{red}username: {white}faraday \n{red}password:{white} {random_password}\n".format(random_password=random_password, white=Fore.WHITE, red=Fore.RED))
            print("{yellow}WARNING{white}: If you are going to execute couchdb importer you must use the couchdb password for faraday user.".format(white=Fore.WHITE, yellow=Fore.YELLOW))

    @staticmethod
    def _save_user_xml(random_password):
        user_xml = os.path.expanduser("~/.faraday/config/user.xml")
        if not os.path.exists(user_xml):
            shutil.copy(FARADAY_BASE_CONFIG_XML, user_xml)
        conf = Configuration(user_xml)
        conf.setAPIUrl('http://localhost:5985')
        conf.setAPIUsername('faraday')
        conf.setAPIPassword(random_password)
        conf.saveConfig()

    @staticmethod
    def _configure_existing_postgres_user():
        username = raw_input('Please enter the postgresql username: ')
        password = getpass.getpass('Please enter the postgresql password: ')

        return username, password

    @staticmethod
    def _check_psql_output(current_psql_output_file, process_status):
        current_psql_output_file.seek(0)
        psql_output = current_psql_output_file.read()
        if 'unknown user: postgres' in psql_output:
            print('ERROR: Postgres user not found. Did you install package {blue}postgresql{white}?'.format(blue=Fore.BLUE, white=Fore.WHITE))
        elif 'could not connect to server' in psql_output:
            print('ERROR: {red}PostgreSQL service{white} is not running. Please verify that it is running in port 5432 before executing setup script.'.format(red=Fore.RED, white=Fore.WHITE))
        elif process_status > 0:
            current_psql_output_file.seek(0)
            print('ERROR: ' + psql_output)

        if process_status is not 0:
            current_psql_output_file.close()  # delete temp file
            sys.exit(process_status)

    @staticmethod
    def generate_random_pw(pwlen):
        rng = SystemRandom()
        return "".join([rng.choice(string.ascii_letters + string.digits) for _ in xrange(pwlen)])

    def _configure_new_postgres_user(self, hostname, psql_log_file):
        """
            This step will create the role on the database.
            we return username and password and those values will be saved in the config file.
        """
        print('This script will {blue} create a new postgres user {white} and {blue} save faraday-server settings {white}(server.ini). '.format(blue=Fore.BLUE, white=Fore.WHITE))
        username = 'faraday_postgresql'
        postgres_command = ['sudo', '-u', 'postgres', 'psql']
        if sys.platform == 'darwin':
            print('{blue}MAC OS detected{white}'.format(blue=Fore.BLUE, white=Fore.WHITE))
            postgres_command = ['psql', 'postgres']
        password = self.generate_random_pw(25)
        if not self.host_local:
            command = postgres_command + ['-c', '"CREATE ROLE {0} WITH LOGIN PASSWORD \'{1}\';"'.format(username, password)]
            return_code = self.execute_remote_command(command, hostname.split(":")[0], psql_log_file)
        else:
            command = postgres_command + ['-c', 'CREATE ROLE {0} WITH LOGIN PASSWORD \'{1}\';'.format(username, password)]
            p = Popen(command, stderr=psql_log_file, stdout=psql_log_file)
            p.wait()
            return_code = p.returncode
        psql_log_file.seek(0)
        output = psql_log_file.read()
        already_exists_error = 'role "{0}" already exists'.format(username)
        if already_exists_error in output:
            print("{yellow}WARNING{white}: Role {username} already exists, skipping creation ".format(yellow=Fore.YELLOW, white=Fore.WHITE, username=username))

            try:
                if getattr(server.config, 'database', None):
                    print('Manual configuration? \n faraday_postgresql was found in PostgreSQL, but no connection string was found in server.ini. ')
                    print('Please configure [database] section with correct postgresql string. Ex. postgresql+psycopg2://faraday_postgresql:PASSWORD@{server}/faraday'.format(server=hostname))
                    sys.exit(1)
                password = server.config.database.connection_string.split(':')[2].split('@')[0]
                host, port = hostname.split(":")
                connection = psycopg2.connect(dbname='postgres',
                                              user=username,
                                              password=password,
                                              host=host,
                                              port=port)
                cur = connection.cursor()
                cur.execute('SELECT * FROM pg_catalog.pg_tables;')
                cur.fetchall()
                connection.commit()
                connection.close()
            except psycopg2.Error as e:
                if 'authentication failed' in e.message:
                    print('{red}ERROR{white}: User {username} already '
                          'exists'.format(white=Fore.WHITE,
                                          red=Fore.RED,
                                          username=username))
                    sys.exit(1)
                else:
                    raise
            return_code = 0
        return username, password, return_code

    def _create_database(self, hostname, database_name, username, psql_log_file):
        """
             This step uses the createdb command to add a new database.
        """
        postgres_command = ['sudo', '-u', 'postgres']
        if sys.platform == 'darwin':
            postgres_command = []

        print('Creating database {0}'.format(database_name))
        command = postgres_command + ['createdb', '-O', username, database_name]
        if not self.host_local:
            return_code = self.execute_remote_command(command, hostname.split(":")[0], psql_log_file)
        else:
            p = Popen(command, stderr=psql_log_file, stdout=psql_log_file)
            p.wait()
            return_code = p.returncode
        psql_log_file.seek(0)
        output = psql_log_file.read()
        already_exists_error = 'database creation failed: ERROR:  database "{0}" already exists'.format(database_name)
        if already_exists_error in output:
            print('{yellow}WARNING{white}: Database already exists.'.format(yellow=Fore.YELLOW, white=Fore.WHITE))
            return_code = 0
        return database_name, return_code

    @staticmethod
    def _save_config(config, username, password, database_name, hostname):
        """
             This step saves database configuration to server.ini
        """
        print('Saving database credentials file in {0}'.format(LOCAL_CONFIG_FILE))

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

    @staticmethod
    def _create_tables(conn_string):
        print('Creating tables')
        from server.models import db
        current_app.config['SQLALCHEMY_DATABASE_URI'] = conn_string
        try:
            db.create_all()
        except OperationalError as ex:
            if 'could not connect to server' in ex.message:
                print('ERROR: {red}PostgreSQL service{white} is not running. Please verify that it is running in correct port before executing setup script.'.format(red=Fore.RED, white=Fore.WHITE))
                sys.exit(1)
            elif 'password authentication failed' in ex.message:
                print('ERROR: ')
                sys.exit(1)
            elif 'Ident authentication failed for user "faraday_postgresql"' in ex.message:
                print('ERROR: {red}Could not login to PostgreSQL.{white} Please check your "/var/lib/pgsql/data/pg_hba.conf" config before executing setup script.'.format(red=Fore.RED, white=Fore.WHITE))
                sys.exit(1)
            else:
                raise
        except ProgrammingError as ex:
            print(ex)
            print('Please check postgres user permissions.')
            sys.exit(1)
        except ImportError as ex:
            if 'psycopg2' in ex:
                print(
                    'ERROR: Missing python depency {red}psycopg2{white}. Please install it with {blue}pip install psycopg2'.format(red=Fore.RED, white=Fore.WHITE, blue=Fore.BLUE))
                sys.exit(1)
            else:
                raise
        else:
            from alembic.config import Config
            from alembic import command
            alembic_cfg = Config(os.path.join(os.getcwd(), 'alembic.ini'))
            command.stamp(alembic_cfg, "head")

    @staticmethod
    def make_connection(host, username):
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        ssh_client.connect(hostname=host, username=username)
        return ssh_client

    def execute_remote_command(self, command, hostname, psql_log_file, username="root"):
        with self.make_connection(hostname, username) as conn:
            _, stdout, stderr = conn.exec_command(" ".join(command))
            psql_log_file.write(stdout.read())
            psql_log_file.write(stderr.read())
            return stdout.channel.recv_exit_status()
