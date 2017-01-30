#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

from model.common import factory
from persistence.server import models

__description__ = 'Creates a new note'
__prettyname__ = 'Create Note'


def main(workspace='', args=None, parser=None):
    parser.add_argument('parent', help='Parent ID')
    parser.add_argument('name', help='Note name')
    parser.add_argument('text', help='Note content')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    obj = factory.createModelObject(models.Note.class_signature, parsed_args.name, workspace,
                                    name=parsed_args.name,
                                    text=parsed_args.text,
                                    parent_id=parsed_args.parent
                                    )

    old = models.get_note(workspace, obj.getID())

    if old is None:
        if not parsed_args.dry_run:
            models.create_note(workspace, obj)
    else:
        print "A note with ID %s already exists!" % obj.getID()
        return 2, None

    return 0, obj.getID()
