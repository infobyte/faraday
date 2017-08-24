import os
import sys
import getpass
from subprocess import Popen, PIPE

try:
    from configparser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError

from flask import current_app
from flask_script import Command

from config.globals import CONST_FARADAY_HOME_PATH
from server.config import LOCAL_CONFIG_FILE


class InitDB(Command):

    def _check_current_config(self, config):
        try:
            config.get('database', 'connection_string')
            reconfigure = None
            while not reconfigure:
                reconfigure = raw_input('Database section \e[31m already found. \e[30m Do you want to reconfigure database? (yes/no) ')
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
        config = ConfigParser()
        config.read(LOCAL_CONFIG_FILE)
        if not self._check_current_config(config):
            return
        faraday_path_conf = os.path.expanduser(CONST_FARADAY_HOME_PATH)
        psql_log_filename = os.path.join(faraday_path_conf, 'logs', 'psql_log.log')
        with open(psql_log_filename, 'a+') as psql_log_file:
            username, password = self._configure_postgres(psql_log_file)
            database_name = self._create_database(username, psql_log_file)
        conn_string = self._save_config(config, username, password, database_name)
        self._create_tables(conn_string)

    def _configure_postgres(self, psql_log_file):
        username = raw_input('Please enter the \e[21m database user \e[0m (press enter to use "faraday"): ') or 'faraday'
        postgres_command = ['sudo', '-u', 'postgres']
        password = None
        while not password:
            password = getpass.getpass(prompt='Please enter the \e[21m password for the postgreSQL username \e[0m: ')
            if not password:
                print('Please type a valid password')
        command = postgres_command + ['psql', '-c', 'CREATE ROLE {0} WITH LOGIN PASSWORD \'{1}\';'.format(username, password)]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file)
        p.wait()
        return username, password

    def _create_database(self, username, psql_log_file):
        postgres_command = ['sudo', '-u', 'postgres']
        database_name = raw_input('Please enter the \e[21m database name \e[0m (press enter to use "faraday"): ') or 'faraday'
        print('Creating database {0}'.format(database_name))
        command = postgres_command + ['createdb', '-O', username, database_name]
        p = Popen(command, stderr=psql_log_file, stdout=psql_log_file)
        p.wait()
        return database_name

    def _save_config(self, config, username, password, database_name):
        db_server = 'localhost'
        print('\e[5m\e[39mSaving \e[30m database credentials file in {0}'.format(LOCAL_CONFIG_FILE))

        conn_string = 'postgresql+psycopg2://{username}:{password}@{server}/{database_name}'.format(
            username=username,
            password=password,
            server=db_server,
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
        db.create_all()
