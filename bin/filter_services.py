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

__description__ = 'Filter services by port'
__prettyname__ = 'Filter services'

SERVICES = {
    'http': [80, 443, 8080, 8443],
    'ssh': [22],
    'telnet': [23],
    'vnc': [5900]
}

# FIXME Update when persistence API changes
COLUMNS = {
    'host': lambda service, workspace: models.get_host(workspace, service.id.split('.')[0]).name,
    'host_os': lambda service, workspace: models.get_host(workspace, service.id.split('.')[0]).os,
    'service': lambda service, workspace: service.name,
    'ports': lambda service, workspace: service.ports,
    'protocol': lambda service, workspace: service.protocol,
    'status': lambda service, workspace: service.status,
}


def main(workspace='', args=None, parser=None):
    parser.add_argument('-p', type=int, nargs='+', metavar='port', help='List of ports to filter', default=[])
    parser.add_argument('services', nargs='+', help='List of service names', default=[]),
    parser.add_argument('--columns', help='Comma separated list of columns to show.',
                        default="host,service,ports,protocol,status,host_os", choices=COLUMNS.keys())

    parser.add_argument('-a', help='Showadditional information, like ports filtered and column headers.',
                        action='store_true', dest='additional_info')

    parsed_args = parser.parse_args(args)

    port_list = parsed_args.p

    for service in parsed_args.services:
        if service in SERVICES:
            port_list += SERVICES[service]
        else:
            sys.stderr.write(Fore.YELLOW +
                             "WARNING: Service definition not found. [%s]\n" % service +
                             Fore.RESET)

    if not port_list:
        print "Empty filter set."
        return 1, None

    if parsed_args.additional_info:
        print 'Filtering services for ports: ' + ', '.join(map(str, sorted(port_list)))

    columns = filter(None, parsed_args.columns.split(','))

    if parsed_args.additional_info:
        print '\t'.join(columns)

    fmt = ('{}\t' * len(columns))[:-1]

    for service in models.get_services(workspace):
        for port in service.ports:
            if port in port_list:
                column_data = []

                for column in columns:
                    column_data += [COLUMNS[column](service, workspace)]

                print  fmt.format(*column_data)

    return 0, None
