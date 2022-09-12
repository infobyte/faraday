"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import errno
import logging
import logging.handlers
import os

# Related third party imports
from syslog_rfc5424_formatter import RFC5424Formatter

# Local application imports
import faraday.server.config
from faraday.server.config import CONST_FARADAY_HOME_PATH

LOG_FILE = CONST_FARADAY_HOME_PATH / 'logs' / 'faraday-server.log'
AUDIT_LOG_FILE = CONST_FARADAY_HOME_PATH / 'logs' / 'audit.log'

MAX_LOG_FILE_SIZE = 5 * 1024 * 1024     # 5 MB
MAX_LOG_FILE_BACKUP_COUNT = 5
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s {%(threadName)s} [pid:%(process)d] ' \
             '[%(filename)s:%(lineno)s - %(funcName)s()]  %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
LOGGING_HANDLERS = []
LVL_SETTABLE_HANDLERS = []


def setup_logging():
    if os.environ.get('FARADAY_MANAGE_RUNNING'):
        return
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    if faraday.server.config.logger_config.use_rfc5424_formatter:
        formatter = RFC5424Formatter()
    else:
        formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    setup_console_logging(formatter)

    if not os.environ.get("FARADAY_DISABLE_LOGS"):
        setup_file_logging(formatter, LOG_FILE)
        setup_file_logging(formatter, AUDIT_LOG_FILE, 'audit')


def setup_console_logging(formatter):
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(faraday.server.config.LOGGING_LEVEL)
    add_handler(console_handler)
    LVL_SETTABLE_HANDLERS.append(console_handler)


def setup_file_logging(formatter, log_file, log_name=None):
    create_logging_path(log_file)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=MAX_LOG_FILE_SIZE, backupCount=MAX_LOG_FILE_BACKUP_COUNT)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(faraday.server.config.LOGGING_LEVEL)
    add_handler(file_handler, log_name)
    LVL_SETTABLE_HANDLERS.append(file_handler)


def add_handler(handler, log_name=None):
    logger = logging.getLogger(log_name)
    logger.addHandler(handler)
    logger.propagate = False
    LOGGING_HANDLERS.append(handler)


def set_logging_level(level):
    faraday.server.config.LOGGING_LEVEL = level
    for handler in LVL_SETTABLE_HANDLERS:
        handler.setLevel(level)


def create_logging_path(path_file):
    try:
        path_file.parent.mkdir(parents=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


setup_logging()
