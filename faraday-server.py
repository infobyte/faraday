#!/usr/bin/env python2.7
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import argparse
import sys

from server.utils.logger import setup_logging, get_logger
from server.config import REQUIREMENTS_FILE

from utils.dependencies import DependencyChecker
from utils.user_input import query_yes_no


def check_dependencies():
    logger = get_logger(__name__)
    checker = DependencyChecker(REQUIREMENTS_FILE)
    missing = checker.check_dependencies()
    if len(missing) > 0:
        logger.warning("The following packages are not installed:")
        for package in missing:
            logger.warning("%s" % package)
        res = query_yes_no("Do you want to install them?", default="no")
        if res:
            checker.install_packages(missing)
            missing = checker.check_dependencies()
    return len(missing) == 0


def main():
    cli_arguments = parse_arguments()
    setup_logging()
    logger = get_logger(__name__)
    if not check_dependencies():
        logger.error("Dependencies not met")
        sys.exit(1)
    import server.web
    import server.database
    server.config.gen_web_config()
    server.database.setup()

    web_server = server.web.WebServer(enable_ssl=cli_arguments.ssl)
    logger.info('Faraday Server is ready')
    web_server.run()
    
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', action='store_true', help='Enable HTTPS')
    return parser.parse_args()

if __name__ == '__main__':
    main()

