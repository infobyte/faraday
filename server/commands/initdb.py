'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import getpass
import shutil
import string

import os
import sys
import psycopg2
from random import SystemRandom
from tempfile import TemporaryFile
from subprocess import Popen, PIPE

import sqlalchemy
from sqlalchemy import create_engine

from config.configuration import getInstanceConfiguration
from faraday import FARADAY_USER_CONFIG_XML, FARADAY_BASE_CONFIG_XML, \
    FARADAY_BASE

try:
    # py2.7
    from configparser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    # py3
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError

from flask import current_app
from colorama import init
from colorama import Fore
from sqlalchemy.exc import OperationalError

from config.globals import CONST_FARADAY_HOME_PATH
from server.config import LOCAL_CONFIG_FILE
init()


class InitDB():

    def _check_current_config(self, config):
        try:
            config.get('database', 'connection_string')
            reconfigure = None
            while not reconfigure:
                reconfigure = raw_input('Database section {yellow} already found{white}. Do you want to reconfigure database? (yes/no) '.format(yellow=Fore.YELLOW, white=Fore.WHITE))
                if reconfigure.lower() == 'no':
                    return False
                elif reconfigure.lower() == 'yes':
                   continue
                else:
                    reconfigure = None
        except NoSectionError:
            config.add_section('database')

        return True

    def run(self):
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
            faraday_path_conf = os.path.expanduser(CONST_FARADAY_HOME_PATH)
            # we use psql_log_filename for historical saving. we will ask faraday users this file.
            # current_psql_output is for checking psql command already known errors for each execution.
            psql_log_filename = os.path.join(faraday_path_conf, 'logs', 'psql_log.log')
            current_psql_output = TemporaryFile()
            with open(psql_log_filename, 'a+') as psql_log_file:
                hostname = 'localhost'
                username, password, process_status = self._configure_new_postgres_user(current_psql_output)
                current_psql_output.seek(0)
                psql_output = current_psql_output.read()
                # persist log in the faraday log psql_log.log
                psql_log_file.write(psql_output)
                self._check_psql_output(current_psql_output, process_status)

                if hostname.lower() in ['localhost', '127.0.0.1']:
                    database_name = 'faraday'
                    current_psql_output = TemporaryFile()
                    database_name, process_status = self._create_database(database_name, username, current_psql_output)
                    current_psql_output.seek(0)
                    self._check_psql_output(current_psql_output, process_status)

            current_psql_output.close()
            conn_string = self._save_config(config, username, password, database_name, hostname)
            self._create_tables(conn_string)
            self._create_admin_user(conn_string)
        except KeyboardInterrupt:
            current_psql_output.close()
            print('User cancelled.')
            sys.exit(1)

    def _create_admin_user(self, conn_string):
        engine = create_engine(conn_string)
        random_password = self.generate_random_pw(12)
        already_created = False
        try:
            engine.execute("INSERT INTO \"faraday_user\" (username, name, password, "
                       "is_ldap, active, last_login_ip, current_login_ip, role) VALUES ('faraday', 'Administrator', "
                       "'{0}', false, true, '127.0.0.1', '127.0.0.1', 'admin');".format(random_password))
        except sqlalchemy.exc.IntegrityError:
            # when re using database user could be created previusly
            already_created = True
            print(
            "{yellow}WARNING{white}: Faraday administrator user already exists.".format(
                yellow=Fore.YELLOW, white=Fore.WHITE))
        if not already_created:
            if not os.path.isfile(FARADAY_USER_CONFIG_XML):
                shutil.copy(FARADAY_BASE_CONFIG_XML, FARADAY_USER_CONFIG_XML)

            print("Admin user created with \n\n{red}username: {white}faraday \n"
                  "{red}password:{white} {"
                  "random_password} \n".format(random_password=random_password,
                                            white=Fore.WHITE, red=Fore.RED))
            print("{yellow}WARNING{white}: If you are going to execute couchdb importer you must use the couchdb password for faraday user.".format(white=Fore.WHITE, yellow=Fore.YELLOW))


    def _configure_existing_postgres_user(self):
        username = raw_input('Please enter the postgresql username: ')
        password = getpass.getpass('Please enter the postgresql password: ')

        return username, password

    def _check_psql_output(self, current_psql_output_file, process_status):
        psql_output = current_psql_output_file.read()
        if 'unknown user: postgres' in psql_output:
            print('ERROR: Postgres user not found. Did you install package {blue}postgresql{white}?'.format(blue=Fore.BLUE, white=Fore.WHITE))
        elif 'could not connect to server' in psql_output:
            print('ERROR: {red}PostgreSQL service{white} is not running. Please verify that it is running in port 5432 before executing setup script.'.format(red=Fore.RED, white=Fore.WHITE))
        elif process_status > 0:
            current_psql_output_file.seek(0)
            print('ERROR: ' + current_psql_output_file.read())

        if process_status is not 0:
            current_psql_output_file.close() # delete temp file
            sys.exit(process_status)

    def generate_random_pw(self, pwlen):
        rng = SystemRandom()
        return "".join([rng.choice(string.ascii_letters + string.digits) for _ in xrange(pwlen)])

    def _configure_new_postgres_user(self, psql_log_file):
        """
            This step will create the role on the database.
            we return username and password and those values will be saved in the config file.
        """
        print('This script will {blue} create a new postgres user {white} and {blue} save faraday-server settings {white}(server.ini). '.format(blue=Fore.BLUE, white=Fore.WHITE))
        username = 'faraday'
        postgres_command = ['sudo', '-u', 'postgres']
        if sys.platform == 'darwin':
            postgres_command = []
        password = self.generate_random_pw(25)
        command = postgres_command + ['psql', '-c', 'CREATE ROLE {0} WITH LOGIN PASSWORD \'{1}\';'.format(username, password)]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file)
        p.wait()
        psql_log_file.seek(0)
        output = psql_log_file.read()
        already_exists_error = 'role "{0}" already exists'.format(username)
        return_code = p.returncode
        if already_exists_error in output:
            print("{yellow}WARNING{white}: Role {username} already exists, skipping creation ".format(yellow=Fore.YELLOW, white=Fore.WHITE, username=username))

            try:
                connection = psycopg2.connect(dbname='postgres',
                                              user=username,
                                              password=password)
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

    def _create_database(self, database_name, username, psql_log_file):
        """
             This step uses the createdb command to add a new database.
        """
        postgres_command = ['sudo', '-u', 'postgres']
        if sys.platform == 'darwin':
            postgres_command = []

        print('Creating database {0}'.format(database_name))
        command = postgres_command + ['createdb', '-O', username, database_name]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file, cwd='/tmp')
        p.wait()
        return_code = p.returncode
        psql_log_file.seek(0)
        output = psql_log_file.read()
        already_exists_error = 'database creation failed: ERROR:  database "{0}" already exists'.format(database_name)
        if already_exists_error in output:
            print('{yellow}WARNING{white}: Database already exists.'.format(yellow=Fore.YELLOW, white=Fore.WHITE))
            return_code = 0
        return database_name, return_code

    def _save_config(self, config, username, password, database_name, hostname):
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
        alembic_config = ConfigParser()
        alembic_config_filename = os.path.join(FARADAY_BASE, 'alembic.ini')
        print(alembic_config_filename)
        alembic_config.read(alembic_config_filename)
        print('Saving database credentials file in {0}'.format(
            alembic_config_filename))
        alembic_config.set('alembic', 'sqlalchemy.url', conn_string)
        with open(alembic_config_filename, 'w') as configfile:
            alembic_config.write(configfile)
        return conn_string

    def _create_tables(self, conn_string):
        print('Creating tables')
        from server.models import db
        current_app.config['SQLALCHEMY_DATABASE_URI'] = conn_string
        try:
            db.create_all()
        except OperationalError as ex:
            if 'could not connect to server' in ex.message:
                print('ERROR: {red}PostgreSQL service{white} is not running. Please verify that it is running in port 5432 before executing setup script.'.format(red=Fore.RED, white=Fore.WHITE))
                sys.exit(1)
            elif 'password authentication failed' in ex.message:
                print('ERROR: ')
            else:
                raise
        except ImportError as ex:
            if 'psycopg2' in ex:
                print(
                    'ERROR: Missing python depency {red}psycopg2{white}. Please install it with {blue}pip install psycopg2'.format(red=Fore.RED, white=Fore.WHITE, blue=Fore.BLUE))
                sys.exit(1)
            else:
                raise
