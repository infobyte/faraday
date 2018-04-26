#!/usr/bin/env python2.7
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import sys
import argparse
import subprocess

import server.config
import server.couchdb
import server.utils.logger
from server.utils import daemonize
from utils import dependencies
from utils.user_input import query_yes_no
from faraday import FARADAY_BASE

logger = server.utils.logger.get_logger(__name__)


def setup_environment(check_deps=False):
    # Configuration files generation
    server.config.copy_default_config_to_local()

    if check_deps:

        # Check dependencies
        installed_deps, missing_deps = dependencies.check_dependencies(
            requirements_file=server.config.REQUIREMENTS_FILE)

        logger.info("Checking dependencies...")

        if missing_deps:

            install_deps = query_yes_no("Do you want to install them?", default="no")

            if install_deps:
                dependencies.install_packages(missing_deps)
                logger.info("Dependencies installed. Please launch Faraday Server again.")
                sys.exit(0)
            else:
                logger.error("Dependencies not met. Please refer to the documentation in order to install them. [%s]",
                             ", ".join(missing_deps))

        logger.info("Dependencies met")

    # Web configuration file generation
    server.config.gen_web_config()

    # Reports DB creation
    server.couchdb.push_reports()


def import_workspaces():
    import server.importer
    server.importer.import_workspaces()


def stop_server():
    if not daemonize.stop_server():
        # Exists with an error if it couldn't close the server
        return False
    else:
        logger.info("Faraday Server stopped successfully")
        return True


def is_server_running():
    pid = daemonize.is_server_running()
    if pid is not None:
        logger.error("Faraday Server is already running. PID: {}".format(pid))
        return True
    else:
        return False


def run_server(args):
    import server.web

    server.database.initialize()
    server.app.setup()
    web_server = server.web.WebServer(enable_ssl=args.ssl)

    daemonize.create_pid_file()
    logger.info('Faraday Server is ready')

    if args.ssl:
        protocol = "https"
    else:
        protocol = "http"

    logger.info('Web interface ready at %s://%s:%d/_ui/' % (
        protocol,
        server.config.faraday_server.bind_address,
        int(server.config.faraday_server.port)
        ))

    web_server.run()


def main():
    os.chdir(FARADAY_BASE)
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', action='store_true', help='enable HTTPS')
    parser.add_argument('--debug', action='store_true', help='run Faraday Server in debug mode')
    parser.add_argument('--start', action='store_true', help='run Faraday Server in background')
    parser.add_argument('--stop', action='store_true', help='stop Faraday Server')
    parser.add_argument('--nodeps', action='store_true', help='Skip dependency check')
    parser.add_argument('--no-setup', action='store_true', help=argparse.SUPPRESS)

    f = open(server.config.VERSION_FILE)
    f_version = f.read().strip()

    parser.add_argument('-v', '--version', action='version',
                        version='Faraday v{version}'.format(version=f_version))

    args = parser.parse_args()

    if args.debug:
        server.utils.logger.set_logging_level(server.config.DEBUG)

    if args.stop:
        sys.exit(0 if stop_server() else 1)

    if is_server_running():
        sys.exit(1)

    # Overwrites config option if SSL is set by argument
    if args.ssl:
        server.config.ssl.set('enabled', 'true')

    if not args.no_setup:
        setup_environment(not args.nodeps)
        import_workspaces()

    if args.start:
        # Starts a new process on background with --ignore-setup
        # and without --start nor --stop
        devnull = open('/dev/null', 'w')
        params = ['/usr/bin/env', 'python2.7', os.path.join(server.config.FARADAY_BASE, __file__), '--no-setup']
        if args.ssl: params.append('--ssl')
        if args.debug: params.append('--debug')
        logger.info('Faraday Server is running as a daemon')
        subprocess.Popen(params, stdout=devnull, stderr=devnull)
    else:
        run_server(args)


if __name__ == '__main__':
    main()
