#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import logging
import logging.config
import os

logname = 'log.conf'

logpath = os.path.dirname(os.path.realpath(__file__))
logfile = os.path.join(logpath, logname)
logging.config.fileConfig(logfile)

def getLogger(obj):
    """Creates a logger named by a string or an object's class name.
     Allowing logger to additionally accept strings as names for non-class loggings.
    """
    if type(obj) is str:
        logger = logging.getLogger(obj)
    else:
        logger = logging.getLogger(obj.__class__.__name__)
    return logger
