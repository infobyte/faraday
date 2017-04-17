#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import os

from model.common import factory
from persistence.server import models

__description__ = 'Import every host found in a PCAP file for further scanning'
__prettyname__ = 'Import PCAP'


def main(workspace='', args=None, parser=None):

    parser.add_argument('-s', '--source', nargs='*', help='Filter packets by source'),
    parser.add_argument('-d', '--dest', nargs='*', help='Filter packets by destination'),

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output from the pcapfile library.')
    parser.add_argument('pcap', help='Path to the PCAP file'),

    parsed_args = parser.parse_args(args)

    try:
        from pcapfile import savefile
        import pcapfile
    except ImportError:
        print 'capfile not found, please install it to use this plugin.' \
              ' You can do it executing pip2 install pcapfile in a shell.'
        return 1, None

    if not os.path.isfile(parsed_args.pcap):
        print "pcap file not found: " % parsed_args.pcap
        return 2, None

    testcap = open(parsed_args.pcap, 'rb')

    try:
        capfile = savefile.load_savefile(testcap, layers=2, verbose=parsed_args.verbose)
    except pcapfile.Error:
        print "Invalid pcap file"
        return 3, None

    print 'pcap file loaded. Parsing packets...'

    # Set() to store already added hosts. This will save an enormous amount of time by not querying the database
    # for hosts we already know are in Faraday
    added = set()

    for packet in capfile.packets:

        if packet.packet.type != 2048:
            continue

        src = packet.packet.payload.src
        dst = packet.packet.payload.dst

        if parsed_args.source and not src in parsed_args.source:
            continue

        if parsed_args.dest and not dst in parsed_args.dest:
            continue

        if src not in added:

            # Lets save additional queries for this IP, it will already be on the database anyway!
            added.add(packet.packet.payload.src)

            # Parsing of source field
            obj = factory.createModelObject(models.Host.class_signature, src,
                                            workspace, os=None, parent_id=None)

            old = models.get_host(workspace, obj.getID())

            if old is None:
                if not parsed_args.dry_run:
                    models.create_host(workspace, obj)
                print '%s\t%s' % (src, obj.getID())

        if dst not in added:

            # Lets save additional queries for this IP, it will already be on the database anyway!
            added.add(packet.packet.payload.dst)

            # Parsing of destination field
            obj = factory.createModelObject(models.Host.class_signature, dst,
                                            workspace, os=None, parent_id=None)

            old = models.get_host(workspace, obj.getID())

            if old is None:
                if not parsed_args.dry_run:
                    models.create_host(workspace, obj)
                print '%s\t%s' % (dst, obj.getID())

    return 0, None
