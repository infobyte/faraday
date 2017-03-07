#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from colorama import Fore
import sys

from persistence.server import models

__description__ = 'Filter services by port or service name'
__prettyname__ = 'Filter services'

SERVICES = {
    'http': [80, 443, 8080, 8443],
    'ftp': [21],
    'ssh': [22],
    'telnet': [23],
    'smtp': [25],
    'domain': [53],
    'pop3': [110, 995],
    'imap': [143, 993],
    'vnc': [5900],
}

# FIXME Update when persistence API changes
COLUMNS = {
    'host': lambda service, workspace: models.get_host(workspace, service.id.split('.')[0]).name,
    'host_os': lambda service, workspace: models.get_host(workspace, service.id.split('.')[0]).os,
    'service': lambda service, workspace: service.name,
    'ports': lambda service, workspace: str(service.ports[0]),
    'protocol': lambda service, workspace: service.protocol,
    'status': lambda service, workspace: service.status,
}


def main(workspace='', args=None, parser=None):
    parser.add_argument('-p', type=int, nargs='+', metavar='port', help='List of ports to filter', default=[])
    parser.add_argument('services', nargs='*', help='List of service names', default=[]),
    parser.add_argument('--columns', help='Comma separated list of columns to show.',
                        default="host,service,ports,protocol,status,host_os", choices=COLUMNS.keys())

    parser.add_argument('--status', help='Comma separated list of status to filter for.')

    parser.add_argument('-a', help='Show additional information, like ports filtered and column headers.',
                        action='store_true', dest='additional_info')

    parser.add_argument('-f', help='Do not apply any filter. Print every host.',
                        action='store_true', dest='no_filter')

    parser.add_argument('-s', '--sorted', help='Print the list sorted IP..', action='store_true')

    parsed_args = parser.parse_args(args)

    port_list = parsed_args.p

    for service in parsed_args.services:
        if service in SERVICES:
            port_list += SERVICES[service]
        else:
            sys.stderr.write(Fore.YELLOW +
                             "WARNING: Service definition not found. [%s]\n" % service +
                             Fore.RESET)

    if not port_list and not parsed_args.no_filter:
        print "Empty filter set."
        return 1, None

    if parsed_args.additional_info and not parsed_args.no_filter:
        print 'Filtering services for ports: ' + ', '.join(map(str, sorted(port_list)))

    columns = filter(None, parsed_args.columns.split(','))

    status_filter = None

    if parsed_args.status is not None:
        status_filter = filter(None, parsed_args.status.split(','))

    lines = []

    for service in models.get_services(workspace):
        for port in service.ports:
            if port in port_list or parsed_args.no_filter:

                if not parsed_args.no_filter and status_filter is not None and not service.status in status_filter:
                    continue

                column_data = []

                for column in columns:
                    column_data += [COLUMNS[column](service, workspace)]

                lines += [column_data]

    if not lines:
        print "No services running on that port found."
        return 0, None

    col_width = max(len(word) for row in lines for word in row) + 2

    if parsed_args.additional_info:
        print ''.join(col.ljust(col_width) for col in columns)
        print '-' * (col_width * len(columns))

    if parsed_args.sorted:
        # Compare lines using the first column (IP)
        for row in sorted(lines, cmp=lambda l1, l2: cmp(l1[0], l2[0])):
            print  "".join(word.ljust(col_width) for word in row)
    else:
        for row in lines:
            print "".join(word.ljust(col_width) for word in row)

    return 0, None
