#!/usr/bin/env python2.7
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import sys
import argparse
import server.config

from server.utils import daemonize
from server.utils.logger import setup_logging, get_logger, set_logging_level
from utils.dependencies import DependencyChecker
from utils.user_input import query_yes_no


def main():
    setup_logging()

    cli_arguments = parse_arguments()

    process_run_commands(cli_arguments)
    setup_environment(cli_arguments)
    setup_and_run_server(cli_arguments)

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', action='store_true', help='enable HTTPS')
    parser.add_argument('--debug', action='store_true', help='run Faraday Server in debug mode')
    parser.add_argument('--start', action='store_true', help='run Faraday Server in background')
    parser.add_argument('--stop', action='store_true', help='stop Faraday Server')
    return parser.parse_args()

def process_run_commands(cli_arguments):
    logger = get_logger(__name__)

    if cli_arguments.stop:
        if not daemonize.stop_server():
            # Exists with an error if it couldn't close the server
            sys.exit(1)
        else:
            logger.info("Faraday Server stopped successfully")
            sys.exit(0)

    # Check if server is already running
    pid = daemonize.is_server_running()
    if pid is not None:
        logger.error("Faraday Server is already running. PID: {}".format(pid))
        sys.exit(1)

def setup_environment(cli_arguments):
    logger = get_logger(__name__)
    server.config.copy_default_config_to_local()

    if cli_arguments.debug:
        set_logging_level(server.config.DEBUG)

    missing_packages = check_dependencies()

    if len(missing_packages) > 0:
        answer = ask_to_install(missing_packages)
        if answer:
            logger.info(
                "Dependencies installed. Please launch Faraday Server again")
            sys.exit(0)
        else:
            logger.error("Dependencies not met")
            sys.exit(1)

    server.config.gen_web_config()

def check_dependencies():
    checker = DependencyChecker(server.config.REQUIREMENTS_FILE)
    missing = checker.check_dependencies()
    return missing

def ask_to_install(missing_packages):
    logger = get_logger(__name__)
    logger.warning("The following packages are not installed:")
    for package in missing_packages:
        logger.warning("%s" % package)
    res = query_yes_no("Do you want to install them?", default="no")
    if res:
        checker = DependencyChecker(server.config.REQUIREMENTS_FILE)
        checker.install_packages(missing_packages)
    return res

def setup_and_run_server(cli_arguments):
    import server.web
    import server.database

    server.database.setup()

    web_server = server.web.WebServer(enable_ssl=cli_arguments.ssl)
    get_logger().info('Faraday Server is ready')

    # Now that server is ready to go, run in background if requested
    if cli_arguments.start:
        daemonize.start_server()

    daemonize.create_pid_file()

    web_server.run()

if __name__ == '__main__':
    main()

