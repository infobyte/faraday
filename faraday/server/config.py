# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os
import shutil
import errno
from configparser import ConfigParser
import logging

from logging import (
    DEBUG,
    INFO,

)
from pathlib import Path


CONST_FARADAY_HOME_PATH = Path(
    os.getenv('FARADAY_HOME', Path('~/').expanduser())
) / '.faraday'

LOGGING_LEVEL = INFO

FARADAY_BASE = Path(__file__).parent.parent
FARADAY_SERVER_SESSIONS_DIR = CONST_FARADAY_HOME_PATH / 'session'
if not CONST_FARADAY_HOME_PATH.exists():
    CONST_FARADAY_HOME_PATH.mkdir()
if not FARADAY_SERVER_SESSIONS_DIR.exists():
    FARADAY_SERVER_SESSIONS_DIR.mkdir()
FARADAY_SERVER_PID_FILE = CONST_FARADAY_HOME_PATH / \
                          'faraday-server-port-{0}.pid'
REQUIREMENTS_FILE = FARADAY_BASE / 'requirements.txt'
DEFAULT_CONFIG_FILE = FARADAY_BASE / 'server' / 'default.ini'
REPORTS_VIEWS_DIR = FARADAY_BASE / 'views' / 'reports'
LOCAL_CONFIG_FILE = CONST_FARADAY_HOME_PATH / 'config' / 'server.ini'
LOCAL_REPORTS_FOLDER = CONST_FARADAY_HOME_PATH / 'uploaded_reports'

CONFIG_FILES = [DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE]

logger = logging.getLogger(__name__)

if not LOCAL_REPORTS_FOLDER.exists():
    try:
        LOCAL_REPORTS_FOLDER.mkdir(parents=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def copy_default_config_to_local():
    if LOCAL_CONFIG_FILE.exists():
        return

    # Create directory if it doesn't exist
    try:
        LOCAL_CONFIG_FILE.parent.mkdir(parents=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    # Copy default config file into faraday local config
    shutil.copyfile(DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE)
    logger.info(f"Local faraday-server configuration created at {LOCAL_CONFIG_FILE}")


def parse_and_bind_configuration():
    """Load configuration from files declared in this module and put them
    on this module's namespace for convenient access"""

    __parser = ConfigParser()
    __parser.read(CONFIG_FILES)

    for section_name in __parser.sections():
        ConfigSection.parse_section(section_name, __parser._sections[section_name])


def is_debug_mode():
    return LOGGING_LEVEL is DEBUG


class ConfigSection:
    def parse(self, __parser):
        for att in self.__dict__:
            value = __parser.get(att)
            if value is None:
                continue
            if isinstance(self.__dict__[att], bool):
                if value in ("yes", "true", "t", "1", "True"):
                    self.__setattr__(att, True)
                else:
                    self.__setattr__(att, False)
            elif isinstance(self.__dict__[att], int):
                self.__setattr__(att, int(value))

            else:
                self.__setattr__(att, value)

    def set(self, option_name, value):
        return self.__setattr__(option_name, value)

    @staticmethod
    def parse_section(section_name, __parser):
        section = None
        if section_name == 'database':
            section = database
        elif section_name == 'faraday_server':
            section = faraday_server
        elif section_name == 'storage':
            section = storage
        elif section_name == 'logger':
            section = logger_config
        elif section_name == 'limiter':
            section = limiter_config
        else:
            return
        section.parse(__parser)


class DatabaseConfigObject(ConfigSection):
    def __init__(self):
        self.connection_string = None


class LimiterConfigObject(ConfigSection):
    def __init__(self):
        self.enabled = False
        self.login_limit = "10/minutes"


class FaradayServerConfigObject(ConfigSection):
    def __init__(self):
        self.bind_address = "127.0.0.1"
        self.port = 5985
        self.secret_key = None
        self.websocket_port = 9000
        self.session_timeout = 12
        self.api_token_expiration = 43200  # Default as 12 hs
        self.agent_registration_secret = None
        self.agent_token_expiration = 60  # Default as 1 min
        self.debug = False
        self.reports_pool_size = 1
        self.delete_report_after_process = True


class StorageConfigObject(ConfigSection):
    def __init__(self):
        self.path = None


class LoggerConfig(ConfigSection):
    def __init__(self):
        self.use_rfc5424_formatter = False


database = DatabaseConfigObject()
faraday_server = FaradayServerConfigObject()
storage = StorageConfigObject()
logger_config = LoggerConfig()
limiter_config = LimiterConfigObject()
parse_and_bind_configuration()
