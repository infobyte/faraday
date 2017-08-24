import sys
import getpass
from subprocess import Popen, PIPE

try:
    from configparser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError

from flask import current_app
from flask_script import Command

from server.config import LOCAL_CONFIG_FILE


class InitDB(Command):

    def run(self):
        database_name = raw_input('Please enter the database name (press enter to use "faraday"): ') or 'faraday'
        username = raw_input('Please enter the database user (press enter to use "faraday"): ') or 'faraday'
        postgres_command = ['sudo', '-u', 'postgres']
        password = None
        while not password:
            password = getpass.getpass(prompt='Please enter the password for the postgreSQL username: ')
            if not password:
                print('Please type a valid password')
        command = postgres_command + ['psql', '-c', 'CREATE ROLE {0} WITH LOGIN PASSWORD \'{1}\';'.format(username, password)]
        p = Popen(command)
        p.wait()
        db_server = raw_input('Enter the postgresql address (press enter for localhost): ') or 'localhost'
        print('Creating database {0}'.format(database_name))
        command = postgres_command + ['createdb', '-O', username, database_name]
        p = Popen(command, stdin=PIPE)
        p.wait()

        print('Saving database credentials file in {0}'.format(LOCAL_CONFIG_FILE))
        config = ConfigParser()
        config.read(LOCAL_CONFIG_FILE)
        try:
            config.get('database', 'connection_string')
        except NoSectionError:
            config.add_section('database')

        conn_string = 'postgresql+psycopg2://{username}:{password}@{server}'.format(
            username=username,
            password=password,
            server=db_server,
        )
        config.set('database', 'connection_string', conn_string)
        with open(LOCAL_CONFIG_FILE, 'w') as configfile:
            config.write(configfile)

        print('Creating tables')
        from server.models import db
        current_app.config['SQLALCHEMY_DATABASE_URI'] = conn_string
        db.create_all()
