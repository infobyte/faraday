# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import logging
import logging.handlers
import faraday.server.config
import errno

from syslog_rfc5424_formatter import RFC5424Formatter
from faraday.server.config import CONST_FARADAY_HOME_PATH

LOG_FILE = CONST_FARADAY_HOME_PATH / 'logs' / 'faraday-server.log'

MAX_LOG_FILE_SIZE = 5 * 1024 * 1024     # 5 MB
MAX_LOG_FILE_BACKUP_COUNT = 5
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s {%(threadName)s} [pid:%(process)d] [%(filename)s:%(lineno)s - %(funcName)s()]  %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
LOGGING_HANDLERS = []
LVL_SETTABLE_HANDLERS = []


def setup_logging():
    logger = logging.getLogger()
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
    logger = logging.getLogger()
    logger.addHandler(handler)
    LOGGING_HANDLERS.append(handler)


def set_logging_level(level):
    faraday.server.config.LOGGING_LEVEL = level
    for handler in LVL_SETTABLE_HANDLERS:
        handler.setLevel(level)


def create_logging_path():
    try:
        LOG_FILE.parent.mkdir(parents=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

setup_logging()


# I'm Py3
