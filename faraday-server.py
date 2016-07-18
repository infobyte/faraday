#!/usr/bin/env python2.7
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import argparse
import server.web
import server.database
import server.utils.logger

def main():
    cli_arguments = parse_arguments()
    server.utils.logger.setup()
    server.database.setup()

    web_server = server.web.WebServer(enable_ssl=cli_arguments.ssl)
    web_server.run()
    
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', action='store_true', help='Enable HTTPS')
    return parser.parse_args()

if __name__ == '__main__':
    main()

