#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import logging
import logging.handlers
import os
from config.globals import *

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

FARADAY_USER_HOME = os.path.expanduser(CONST_FARADAY_HOME_PATH)
LOG_FILE = os.path.join(FARADAY_USER_HOME, CONST_FARADAY_LOGS_PATH, 'faraday.log')

# Default logger

logger = logging.getLogger('faraday')
logger.propagate = False
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)


def setUpLogger():
    logger = logging.getLogger('faraday')

    level = logging.INFO
    if CONF.getDebugStatus():
        level = logging.DEBUG

    logger.setLevel(level)
    fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


def getLogger(obj):
    """Creates a logger named by a string or an object's class name.
     Allowing logger to additionally accept strings as names for non-class loggings.
    """
    if type(obj) is str:
        logger = logging.getLogger('%s.%s' % ('faraday', obj))
    else:
        logger = logging.getLogger('%s.%s' % ('faraday', obj.__class__.__name__))
    return logger
