#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import logging

from model.common import factory
from persistence.server import models

__description__ = 'Creates a new note'
__prettyname__ = 'Create Note'

logger = logging.getLogger(__name__)


def main(workspace='', args=None, parser=None):
    logger.warn('Create note will create a comment. fplugin name will be changed to create_comment')
    parser.add_argument('parent', help='Parent ID')
    parser.add_argument('parent_type', help='Parent Type')
    parser.add_argument('name', help='Note name')
    parser.add_argument('text', help='Note content')

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')

    parsed_args = parser.parse_args(args)

    obj = factory.createModelObject(models.Note.class_signature,
                                    parsed_args.name,
                                    workspace,
                                    text=parsed_args.text,
                                    object_id=parsed_args.parent,
                                    object_type=parsed_args.parent_type.lower()
                                    )

    models.create_note(workspace, obj)

    return 0, 1
