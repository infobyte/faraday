# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import logging
import logging.handlers
import faraday.server.config
import errno

from syslog_rfc5424_formatter import RFC5424Formatter

LOG_FILE = os.path.expanduser(os.path.join(
    faraday.server.config.CONST_FARADAY_HOME_PATH,
    'logs',
    'faraday-server.log'))

MAX_LOG_FILE_SIZE = 5 * 1024 * 1024     # 5 MB
MAX_LOG_FILE_BACKUP_COUNT = 5
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s {%(threadName)s} [%(filename)s:%(lineno)s - %(funcName)s()]  %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
ROOT_LOGGER = u'faraday'
LOGGING_HANDLERS = []
LVL_SETTABLE_HANDLERS = []


def setup_logging():
    logger = logging.getLogger(ROOT_LOGGER)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    if faraday.server.config.logger_config.use_rfc5424_formatter:
        formatter = RFC5424Formatter()
    else:

        formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    setup_console_logging(formatter)
    setup_file_logging(formatter)


def setup_console_logging(formatter):
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(faraday.server.config.LOGGING_LEVEL)
    add_handler(console_handler)
    LVL_SETTABLE_HANDLERS.append(console_handler)


def setup_file_logging(formatter):
    create_logging_path()
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_LOG_FILE_SIZE, backupCount=MAX_LOG_FILE_BACKUP_COUNT)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(faraday.server.config.LOGGING_LEVEL)
    add_handler(file_handler)
    LVL_SETTABLE_HANDLERS.append(file_handler)


def add_handler(handler):
    logger = logging.getLogger(ROOT_LOGGER)
    logger.addHandler(handler)
    LOGGING_HANDLERS.append(handler)


def get_logger(obj=None):
    """Creates a logger named by a string or an object's class name.
     Allowing logger to additionally accept strings as names
     for non-class loggings."""
    if obj is None:
        logger = logging.getLogger(ROOT_LOGGER)
    elif isinstance(obj, str):
        if obj != ROOT_LOGGER:
            logger = logging.getLogger(u'{}.{}'.format(ROOT_LOGGER, obj))
        else:
            logger = logging.getLogger(obj)
    else:
        cls_name = obj.__class__.__name__
        logger = logging.getLogger(u'{}.{}'.format(ROOT_LOGGER, cls_name))
    return logger


def set_logging_level(level):
    faraday.server.config.LOGGING_LEVEL = level
    for handler in LVL_SETTABLE_HANDLERS:
        handler.setLevel(level)


def create_logging_path():
    try:
        os.makedirs(os.path.dirname(LOG_FILE))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

setup_logging()


# I'm Py3