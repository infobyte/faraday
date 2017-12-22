import string

import os
import sys
from random import SystemRandom
from tempfile import TemporaryFile
from subprocess import Popen, PIPE

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
            configure_existing_user = None
            with open(psql_log_filename, 'a+') as psql_log_file:
                while configure_existing_user is None:
                    configure_existing_user = raw_input('Do you {blue} already have {white} a postgresql username and password? (yes/no): '.format(blue=Fore.BLUE, white=Fore.WHITE))
                    if configure_existing_user.lower() == 'yes':
                        configure_existing_user = True
                    elif configure_existing_user.lower() == 'no':
                        configure_existing_user = False
                    else:
                        print('Invalid option. Please type "yes" or "no" (ctrl-c to cancel): ')
                        configure_existing_user = None
                hostname = raw_input(
                    'Please enter the postgresql hostname or ip address (enter for "localhost"): ') or 'localhost'

                if not configure_existing_user:
                    if hostname not in ['localhost', '127.0.0.1']:
                        print('ERROR: can only create postgresql user on localhost')
                        sys.exit(1)
                    current_psql_output = TemporaryFile()
                    username, password, process_status = self._configure_new_postgres_user(current_psql_output)
                    current_psql_output.seek(0)
                    psql_output = current_psql_output.read()
                    # persist log in the faraday log psql_log.log
                    psql_log_file.write(psql_output)
                    self._check_psql_output(current_psql_output, process_status)

                    if hostname.lower() in ['localhost', '127.0.0.1']:
                        database_name = raw_input(
                            'Please enter the {blue} database name {white} (press enter to use "faraday"): '.format(
                                blue=Fore.BLUE, white=Fore.WHITE)) or 'faraday'
                        current_psql_output = TemporaryFile()
                        process_status = self._create_database(database_name, username, current_psql_output)
                        current_psql_output.seek(0)
                        self._check_psql_output(current_psql_output, process_status)
                else:
                    username, password = self._configure_existing_postgres_user()
                    database_name = raw_input(
                        'Please enter the {blue} database name {white} (press enter to use "faraday"): '.format(
                            blue=Fore.BLUE, white=Fore.WHITE)) or 'faraday'

            current_psql_output.close()
            conn_string = self._save_config(config, username, password, database_name, hostname)
            self._create_tables(conn_string)
        except KeyboardInterrupt:
            current_psql_output.close()
            print('User cancelled.')
            sys.exit(1)

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
            print('ERROR: ' + psql_output)

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
        username_default = 'faraday_db_admin'
        print('This script will {blue} create a new postgres user {white} and {blue} save faraday-server settings {white}(server.ini). '.format(blue=Fore.BLUE, white=Fore.WHITE))
        username = raw_input('Please enter the new {blue} database username {white} (press enter to use "{0}"): '.format(username_default, blue=Fore.BLUE, white=Fore.WHITE)) or username_default
        postgres_command = ['sudo', '-u', 'postgres']
        password = self.generate_random_pw(25)
        command = postgres_command + ['psql', '-c', 'CREATE ROLE {0} WITH LOGIN PASSWORD \'{1}\';'.format(username, password)]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file)
        p.wait()
        return username, password, p.returncode

    def _create_database(self, database_name, username, psql_log_file):
        """
             This step uses the createdb command to add a new database.
        """
        postgres_command = ['sudo', '-u', 'postgres']
        print('Creating database {0}'.format(database_name))
        command = postgres_command + ['createdb', '-O', username, database_name]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file, cwd='/tmp')
        p.wait()
        return database_name, p.returncode

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
            else:
                raise
        except ImportError as ex:
            if 'psycopg2' in ex:
                print(
                    'ERROR: Missing python depency {red}psycopg2{white}. Please install it with {blue}pip install psycopg2'.format(red=Fore.RED, white=Fore.WHITE, blue=Fore.BLUE))
                sys.exit(1)
            else:
                raise
