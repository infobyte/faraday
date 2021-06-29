# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import sys
import socket
import argparse
import logging

from alembic.runtime.migration import MigrationContext

from colorama import init, Fore
import sqlalchemy
import faraday.server.config
import faraday.server.utils.logger
import faraday.server.web
from faraday.server.models import db, Workspace
from faraday.server.utils import daemonize
from faraday.server.web import get_app
from alembic.script import ScriptDirectory
from alembic.config import Config

logger = logging.getLogger(__name__)

init()


def setup_environment(check_deps=False):
    # Configuration files generation
    faraday.server.config.copy_default_config_to_local()


def is_server_running(port):
    pid = daemonize.is_server_running(port)
    if pid is not None:
        logger.warning(f"Faraday Server is already running. PID: {pid}")
        return True
    else:
        return False


def run_server(args):
    web_server = faraday.server.web.WebServer()
    daemonize.create_pid_file(args.port)
    web_server.run()


def check_postgresql():
    with get_app().app_context():
        try:
            if not db.session.query(Workspace).count():
                logger.warning('No workspaces found')
        except sqlalchemy.exc.ArgumentError:
            logger.error(
                f'\n{Fore.RED}Please check your PostgreSQL connection string in the file ~/.faraday/config/server.ini on your home directory.{Fore.WHITE} \n'
            )
            sys.exit(1)
        except sqlalchemy.exc.OperationalError:
            logger.error(
                    '\n\n{RED}Could not connect to PostgreSQL.\n{WHITE}Please check: \n{YELLOW}  * if database is running \n  * configuration settings are correct. \n\n{WHITE}For first time installations execute{WHITE}: \n\n {GREEN} faraday-manage initdb\n\n'.format(GREEN=Fore.GREEN, YELLOW=Fore.YELLOW, WHITE=Fore.WHITE, RED=Fore.RED))
            sys.exit(1)
        except sqlalchemy.exc.ProgrammingError:
            logger.error(
                    f'\n\nn{Fore.WHITE}Missing migrations, please execute: \n\nfaraday-manage migrate')
            sys.exit(1)


def check_alembic_version():
    config = Config()
    config.set_main_option("script_location", "migrations")
    script = ScriptDirectory.from_config(config)

    head_revision = script.get_current_head()
    with get_app().app_context():
        try:
            conn = db.session.connection()
        except ImportError:
            if not faraday.server.config.database.connection_string:
                print("\n\nNo database configuration found. Did you execute \"faraday-manage initdb\"? \n\n")
                sys.exit(1)
        except sqlalchemy.exc.OperationalError:
            print("Bad Credentials, please check the .faraday/config/server.ini")
            sys.exit(1)

        context = MigrationContext.configure(conn)

        current_revision = context.get_current_revision()
        if head_revision != current_revision:
            version_path = faraday.server.config.FARADAY_BASE / 'migrations'\
                           / 'versions'
            if list(version_path.glob(f'{current_revision}_*.py')):
                print('--' * 20)
                print('Missing migrations, please execute: \n\n')
                print('faraday-manage migrate')
                sys.exit(1)
            else:
                logger.warning(
                    "You are using an unknown schema version. If you are a "
                    "developer, this probably happened because you used branch "
                    "with a schema migration not merged yet. If you are a "
                    "normal user, consider reporting this bug back to us"
                    )


def main():
    os.chdir(faraday.server.config.FARADAY_BASE)
    check_alembic_version()
    # TODO RETURN TO prev CWD
    check_postgresql()
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true', help='run Faraday Server in debug mode')
    parser.add_argument('--nodeps', action='store_true', help='Skip dependency check')
    parser.add_argument('--no-setup', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--port', type=int, help='Overides server.ini port configuration')
    parser.add_argument('--websocket_port', help='Overides server.ini websocket port configuration')
    parser.add_argument('--bind_address', help='Overides server.ini bind_address configuration')
    f_version = faraday.__version__
    parser.add_argument('-v', '--version', action='version', version=f'Faraday v{f_version}')
    args = parser.parse_args()
    if args.debug or faraday.server.config.faraday_server.debug:
        faraday.server.utils.logger.set_logging_level(faraday.server.config.DEBUG)
    args.port = faraday.server.config.faraday_server.port = args.port or \
            faraday.server.config.faraday_server.port or 5985
    if args.bind_address:
        faraday.server.config.faraday_server.bind_address = args.bind_address

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((args.bind_address or faraday.server.config.faraday_server.bind_address,
                              int(args.port or faraday.server.config.faraday_server.port)))
    if is_server_running(args.port) and result == 0:
        sys.exit(1)
    if result == 0:
        logger.error("Faraday Server port in use. Check your processes and run the server again...")
        sys.exit(1)
    if not args.no_setup:
        setup_environment(not args.nodeps)
    if args.websocket_port:
        faraday.server.config.faraday_server.websocket_port = args.websocket_port

    run_server(args)


if __name__ == '__main__':  # Don't delete. this is used for dev
    main()
