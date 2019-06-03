#!/usr/bin/env python2.7
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import sys
import glob
import socket
import argparse
import subprocess


try:
    from colorama import init, Fore
    import sqlalchemy
    import faraday.server.config
    import faraday.server.utils.logger
    from faraday.server.models import db, Workspace
    from faraday.server.utils import daemonize
    from faraday.server.web import app
    from faraday.utils import dependencies
    from faraday.utils.user_input import query_yes_no
    from faraday.server.config import FARADAY_BASE
    from faraday.utils.logs import setUpLogger
    from alembic.script import ScriptDirectory
    from alembic.config import Config
    from alembic.migration import MigrationContext
except ImportError as ex:
    print(ex)
    print('Missing dependencies.\nPlease execute: pip install -r requirements_server.txt')
    sys.exit(1)
logger = faraday.server.utils.logger.get_logger(__name__)
init()


def setup_environment(check_deps=False):
    # Configuration files generation
    faraday.server.config.copy_default_config_to_local()

    if check_deps:

        # Check dependencies
        installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
            requirements_file=faraday.server.config.REQUIREMENTS_FILE)

        logger.info("Checking dependencies...")

        if conflict_deps:
            logger.info("Some dependencies are old. Update them with \"pip install -r requirements_server.txt -U\"")

        logger.info("Dependencies met")

    # Web configuration file generation
    faraday.server.config.gen_web_config()


def stop_server(port):
    if not daemonize.stop_server(port):
        # Exists with an error if it couldn't close the server
        return False
    else:
        return True


def is_server_running(port):
    pid = daemonize.is_server_running(port)
    if pid is not None:
        logger.warn("Faraday Server is already running. PID: {}".format(pid))
        return True
    else:
        return False


def run_server(args):
    import faraday.server.web

    web_server = faraday.server.web.WebServer(enable_ssl=args.ssl)
    daemonize.create_pid_file(args.port)
    web_server.run()

def restart_server(args_port):
    devnull = open('/dev/null', 'w')

    if args_port:
        ports = [args_port]
    else:
        ports = daemonize.get_ports_running()

    if not ports:
        logger.error('Faraday Server is not running')
        sys.exit(1)

    for port in ports:
        stop_server(port)
        params = ['/usr/bin/env', 'python2.7',\
            os.path.join(faraday.server.config.FARADAY_BASE, __file__), '--no-setup', '--port', str(port)]

        logger.info('Restarting Faraday Server...')
        subprocess.Popen(params, stdout=devnull, stderr=devnull)
        logger.info('Faraday Server is running as a daemon in port {}'.format(port))


def check_postgresql():
    with app.app_context():
        try:
            if not db.session.query(Workspace).count():
                logger.warn('No workspaces found. Remember to execute CouchDB importer')
        except sqlalchemy.exc.ArgumentError:
            logger.error(
                '\n\b{RED}Please check your PostgreSQL connection string in the file ~/.faraday/config/server.ini on your home directory.{WHITE} \n'.format(RED=Fore.RED, WHITE=Fore.WHITE)
            )
            sys.exit(1)
        except sqlalchemy.exc.OperationalError:
            logger.error(
                    '\n\n{RED}Could not connect to PostgreSQL.\n{WHITE}Please check: \n{YELLOW}  * if database is running \n  * configuration settings are correct. \n\n{WHITE}For first time installations execute{WHITE}: \n\n {GREEN} faraday-manage initdb\n\n'.format(GREEN=Fore.GREEN, YELLOW=Fore.YELLOW, WHITE=Fore.WHITE, RED=Fore.RED))
            sys.exit(1)


def check_alembic_version():
    config = Config()
    config.set_main_option("script_location", "migrations")
    script = ScriptDirectory.from_config(config)

    head_revision = script.get_current_head()
    with app.app_context():
        try:
            conn = db.session.connection()
        except ImportError as ex:
            if not faraday.server.config.database.connection_string:
                print("\n\nNo database configuration found. Did you execute \"faraday-manage initdb\"? \n\n")
                sys.exit(1)

        context = MigrationContext.configure(conn)

        current_revision = context.get_current_revision()
        if head_revision != current_revision:
            if glob.glob(os.path.join(FARADAY_BASE, 'migrations', 'versions',
                         '{}_*.py'.format(current_revision))):
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
    os.chdir(FARADAY_BASE)
    check_alembic_version()
    check_postgresql()
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', action='store_true', help='enable HTTPS')
    parser.add_argument('--debug', action='store_true', help='run Faraday Server in debug mode')
    parser.add_argument('--start', action='store_true', help='run Faraday Server in background')
    parser.add_argument('--stop', action='store_true', help='stop Faraday Server')
    parser.add_argument('--restart', action='store_true', help='Restart Faraday Server')
    parser.add_argument('--nodeps', action='store_true', help='Skip dependency check')
    parser.add_argument('--no-setup', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--port', help='Overides server.ini port configuration')
    parser.add_argument('--websocket_port', help='Overides server.ini websocket port configuration')
    parser.add_argument('--bind_address', help='Overides server.ini bind_address configuration')

    f_version = faraday.__version__

    parser.add_argument('-v', '--version', action='version',
                        version='Faraday v{version}'.format(version=f_version))

    args = parser.parse_args()
    setUpLogger(args.debug)

    if args.debug:
        faraday.server.utils.logger.set_logging_level(faraday.server.config.DEBUG)

    if args.restart:
        restart_server(args.port)
        sys.exit()

    if args.stop:
        if args.port:
            sys.exit(0 if stop_server(args.port) else 1)
        else:
            ports = daemonize.get_ports_running()
            if not ports:
                logger.info('Faraday Server is not running')
            exit_code = 0
            for port in ports:
                exit_code += 0 if stop_server(port) else 1
            sys.exit(exit_code)

    else:
        if not args.port:
            args.port = '5985'


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((args.bind_address or faraday.server.config.faraday_server.bind_address, int(args.port or faraday.server.config.faraday_server.port)))

    if is_server_running(args.port) and result == 0:
        sys.exit(1)

    if result == 0:
        logger.error("Faraday Server port in use. Check your processes and run the server again...")
        sys.exit(1)

    # Overwrites config option if SSL is set by argument
    if args.ssl:
        faraday.server.config.ssl.enabled = 'true'

    if not args.no_setup:
        setup_environment(not args.nodeps)

    if args.port:
        faraday.server.config.faraday_server.port = args.port

    if args.bind_address:
        faraday.server.config.faraday_server.bind_address = args.bind_address

    if args.websocket_port:
        faraday.server.config.faraday_faraday.server.websocket_port = args.websocket_port

    if args.start:
        # Starts a new process on background with --ignore-setup
        # and without --start nor --stop
        devnull = open('/dev/null', 'w')
        params = ['/usr/bin/env', 'python2.7', os.path.join(faraday.server.config.FARADAY_BASE, __file__), '--no-setup']
        arg_dict = vars(args)
        for arg in arg_dict:
            if arg not in ["start", "stop"] and arg_dict[arg]:
                params.append('--'+arg)
                if arg_dict[arg] != True:
                    params.append(arg_dict[arg])
        logger.info('Faraday Server is running as a daemon')
        subprocess.Popen(params, stdout=devnull, stderr=devnull)

    elif not args.start:
        run_server(args)


if __name__ == '__main__':
    main()
