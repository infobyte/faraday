from __future__ import absolute_import
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os
import shutil
import errno
try:
    import ConfigParser
except ImportError:
    import faraday.client.configparser as ConfigParser

from logging import (
    DEBUG,
    INFO,
)
from faraday import __license_version__ as license_version
from faraday.config import constant as CONSTANTS
from faraday.config.configuration import getInstanceConfiguration

LOGGING_LEVEL = INFO

FARADAY_BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
FARADAY_SERVER_SESSIONS_DIR = os.path.join(CONSTANTS.CONST_FARADAY_HOME_PATH, 'session')
if not os.path.exists(CONSTANTS.CONST_FARADAY_HOME_PATH):
    os.mkdir(CONSTANTS.CONST_FARADAY_HOME_PATH)
if not os.path.exists(FARADAY_SERVER_SESSIONS_DIR):
    # Temporary hack, remove me
    os.mkdir(FARADAY_SERVER_SESSIONS_DIR)
FARADAY_SERVER_PID_FILE = os.path.join(
    CONSTANTS.CONST_FARADAY_HOME_PATH, 'faraday-server-port-{0}.pid')
REQUIREMENTS_FILE = os.path.join(FARADAY_BASE, 'requirements_server.txt')
DEFAULT_CONFIG_FILE = os.path.join(FARADAY_BASE, 'server/default.ini')
REPORTS_VIEWS_DIR = os.path.join(FARADAY_BASE, 'views/reports')
LOCAL_CONFIG_FILE = os.path.expanduser(
    os.path.join(CONSTANTS.CONST_FARADAY_HOME_PATH, 'config/server.ini'))
LOCAL_REPORTS_FOLDER = os.path.expanduser(
    os.path.join(CONSTANTS.CONST_FARADAY_HOME_PATH, 'uploaded_reports/'))

CONFIG_FILES = [DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE]
WS_BLACKLIST = CONSTANTS.CONST_BLACKDBS

if not os.path.exists(LOCAL_REPORTS_FOLDER):
    try:
        os.makedirs(LOCAL_REPORTS_FOLDER)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def copy_default_config_to_local():
    if os.path.exists(LOCAL_CONFIG_FILE):
        return

    # Create directory if it doesn't exist
    try:
        os.makedirs(os.path.dirname(LOCAL_CONFIG_FILE))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    # Copy default config file into faraday local config
    shutil.copyfile(DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE)

    from faraday.server.utils.logger import get_logger
    get_logger(__name__).info(u"Local faraday-server configuration created at {}".format(LOCAL_CONFIG_FILE))


def parse_and_bind_configuration():
    """Load configuration from files declared in this module and put them
    on this module's namespace for convenient access"""

    __parser = ConfigParser.SafeConfigParser()
    __parser.read(CONFIG_FILES)

    for section_name in __parser.sections():
        ConfigSection.parse_section(section_name, __parser._sections[section_name])

def __get_osint():
    try:
        return getInstanceConfiguration().getOsint()
    except:
        return ''


def gen_web_config():
    # Warning: This is publicly accesible via the API, it doesn't even need an
    # authenticated user. Don't add sensitive information here.
    doc = {
        'ver': license_version,
        'lic_db': CONSTANTS.CONST_LICENSES_DB,
        "osint": __get_osint(),
        'vuln_model_db': CONSTANTS.CONST_VULN_MODEL_DB,
        'show_vulns_by_price': dashboard.show_vulns_by_price,
    }
    return doc


def is_debug_mode():
    return LOGGING_LEVEL is DEBUG


class ConfigSection(object):
    def parse(self, __parser):
        for att in self.__dict__:
            if isinstance(self.__dict__[att], bool):
                value = __parser.get(att)
                if value in ("yes", "true", "t", "1", "True"):
                    self.__setattr__(att, True)
                else:
                    self.__setattr__(att, False)

            else:
                self.__setattr__(att, __parser.get(att))

    @staticmethod
    def parse_section(section_name, __parser):
        section = None
        if section_name == 'couchdb':
            section = couchdb
        elif section_name == 'database':
            section = database
        elif section_name == 'dashboard':
            section = dashboard
        elif section_name == 'faraday_server':
            section = faraday_server
        elif section_name == 'ldap':
            section = ldap
        elif section_name == 'ssl':
            section = ssl
        elif section_name == 'storage':
            section = storage
        else:
            return
        section.parse(__parser)


class CouchDBConfigObject(ConfigSection):
    def __init__(self):
        self.host = None
        self.password = None
        self.port = None
        self.protocol = None
        self.ssl_port = None
        self.user = None


class DatabaseConfigObject(ConfigSection):
    def __init__(self):
        self.connection_string = None


class DashboardConfigObject(ConfigSection):
    def __init__(self):
        self.show_vulns_by_price = False


class FaradayServerConfigObject(ConfigSection):
    def __init__(self):
        self.bind_address = None
        self.port = None
        self.secret_key = None
        self.websocket_port = None


class LDAPConfigObject(ConfigSection):
    def __init__(self):
        self.admin_group = None
        self.client_group = None
        self.disconnect_timeout = None
        self.domain_dn = None
        self.enabled = None
        self.pentester_group = None
        self.port = None
        self.server = None
        self.use_ldaps = None
        self.use_start_tls = None


class SSLConfigObject(ConfigSection):
    def __init__(self):
        self.certificate = None
        self.keyfile = None
        self.port = None
        self.enabled = False


class StorageConfigObject(ConfigSection):
    def __init__(self):
        self.path = None



couchdb = CouchDBConfigObject()
database = DatabaseConfigObject()
dashboard = DashboardConfigObject()
faraday_server = FaradayServerConfigObject()
ldap = LDAPConfigObject()
ssl = SSLConfigObject()
storage = StorageConfigObject()

parse_and_bind_configuration()
