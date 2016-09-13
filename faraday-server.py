#!/usr/bin/env python2.7
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import server.utils.logger

import sys, os
import argparse
import subprocess
import server.config

from server.utils import daemonize
from utils.dependencies import DependencyChecker
from utils.user_input import query_yes_no

logger = server.utils.logger.get_logger(__name__)

def main():
    args = parse_arguments()

    if args.stop:
        sys.exit(0 if stop_server() else 1)

    if not args.no_setup:
        setup_environment()
        import_workspaces()

    if is_server_running():
        sys.exit(1)
        
    if args.debug:
        server.utils.logger.set_logging_level(server.config.DEBUG)

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

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', action='store_true', help='enable HTTPS')
    parser.add_argument('--debug', action='store_true', help='run Faraday Server in debug mode')
    parser.add_argument('--start', action='store_true', help='run Faraday Server in background')
    parser.add_argument('--stop', action='store_true', help='stop Faraday Server')
    parser.add_argument('--no-setup', action='store_true', help=argparse.SUPPRESS)
    return parser.parse_args()

def setup_environment():
    # Configuration files generation
    server.config.copy_default_config_to_local()

    # Dependencies installation
    missing_packages = check_dependencies()
    if len(missing_packages) > 0:
        install_packages(missing_packages)
    server.config.gen_web_config()

def check_dependencies():
    checker = DependencyChecker(server.config.REQUIREMENTS_FILE)
    missing = checker.check_dependencies()
    return missing

def install_packages(packages):
    if ask_to_install(packages):
        logger.info("Dependencies installed. Please launch Faraday Server again")
        sys.exit(0)
    else:
        logger.error("Dependencies not met")
        sys.exit(1)

def ask_to_install(missing_packages):
    logger.warning("The following packages are not installed:")
    for package in missing_packages:
        logger.warning("%s" % package)

    if query_yes_no("Do you want to install them?", default="no"):
        checker = DependencyChecker(server.config.REQUIREMENTS_FILE)
        checker.install_packages(missing_packages)

    return res

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
    import server.database
    import server.app
    import server.web

    server.database.initialize()
    server.app.setup()
    web_server = server.web.WebServer(enable_ssl=args.ssl)

    daemonize.create_pid_file()
    logger.info('Faraday Server is ready')
    web_server.run()

if __name__ == '__main__':
    main()

