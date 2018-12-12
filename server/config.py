from __future__ import absolute_import
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os
import shutil
import errno
import ConfigParser

from logging import (
    DEBUG,
    INFO,
)
from config import constant as CONSTANTS
from config.configuration import getInstanceConfiguration
from utils.logs import getLogger

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
VERSION_FILE = os.path.join(FARADAY_BASE, CONSTANTS.CONST_VERSION_FILE)
REPORTS_VIEWS_DIR = os.path.join(FARADAY_BASE, 'views/reports')
LOCAL_CONFIG_FILE = os.path.expanduser(
    os.path.join(CONSTANTS.CONST_FARADAY_HOME_PATH, 'config/server.ini'))
LOCAL_REPORTS_FOLDER = os.path.expanduser(
    os.path.join(CONSTANTS.CONST_FARADAY_HOME_PATH, 'uploaded_reports/'))

CONFIG_FILES = [DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE]
WS_BLACKLIST = CONSTANTS.CONST_BLACKDBS

logger = getLogger(__name__)

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

    from server.utils.logger import get_logger
    get_logger(__name__).info(u"Local faraday-server configuration created at {}".format(LOCAL_CONFIG_FILE))


def parse_and_bind_configuration():
    """Load configuration from files declared in this module and put them
    on this module's namespace for convenient access"""

    __parser = ConfigParser.SafeConfigParser()
    __parser.read(CONFIG_FILES)

    for section_name in __parser.sections():
        ConfigSection.parse_section(section_name, __parser._sections[section_name])

def __get_version():
    try:
        version = open(VERSION_FILE, 'r').read().strip()
    except:
        version = ''
    return version


def __get_osint():
    try:
        return getInstanceConfiguration().getOsint()
    except:
        return ''


def gen_web_config():
    # Warning: This is publicly accesible via the API, it doesn't even need an
    # authenticated user. Don't add sensitive information here.
    doc = {
        'ver': __get_version(),
        'lic_db': CONSTANTS.CONST_LICENSES_DB,
        "osint": __get_osint(),
        'vuln_model_db': CONSTANTS.CONST_VULN_MODEL_DB
    }
    return doc


def is_debug_mode():
    return LOGGING_LEVEL is DEBUG


class ConfigSection(object):
    def parse(self, __parser):
        for att in self.__dict__:
            self.__setattr__(att,__parser.get(att))

    @staticmethod
    def parse_section(section_name, __parser):
        section = None
        if section_name == 'couchdb':
            section = couchdb
        elif section_name == 'database':
            section = database
        elif section_name == 'faraday_server':
            section = faraday_server
        elif section_name == 'ldap':
            section = ldap
        elif section_name == 'ssl':
            section = ssl
        elif section_name == 'storage':
            section = storage
        section.parse(__parser)

    @staticmethod
    def raise_att_error(msg):
        logger.error(msg)
        raise AttributeError(msg)

    @staticmethod
    def raise_att_info(msg):
        logger.info(msg)


class CouchDBConfigObject(ConfigSection):
    _host = 'localhost'
    _password = 'changeme'
    _port = '5984'
    _protocol = None
    _ssl_port = None
    _user = 'faraday'

    def get_host(self):
        if self._host is None:
            self.raise_att_error("Unset host requested")
        return self._host

    def set_host(self, value):
        self._host = value

    def get_password(self):
        if self._password is None:
            self.raise_att_error("Unset password requested")
        return self._password

    def set_password(self, value):
        self._password = value

    def get_port(self):
        if self._port is None:
            self.raise_att_error("Unset port requested")
        return self._port

    def set_port(self, value):
        self._port = value

    def get_protocol(self):
        if self._protocol is None:
            self.raise_att_info("Unset protocol requested")
        return self._protocol

    def set_protocol(self, value):
        self._protocol = value

    def get_ssl_port(self):
        if self._ssl_port is None:
            self.raise_att_info("Unset ssl_port requested")
        return self._ssl_port

    def set_ssl_port(self, value):
        self._ssl_port = value

    def get_user(self):
        if self._user is None:
            self.raise_att_error("Unset user requested")
        return self._user

    def set_user(self, value):
        self._user = value

    host = property(get_host, set_host)
    password = property(get_password, set_password)
    port = property(get_port, set_port)
    protocol = property(get_protocol, set_protocol)
    ssl_port = property(get_ssl_port, set_ssl_port)
    user = property(get_user, set_user)


class DatabaseConfigObject(ConfigSection):
    _connection_string = None
    _set = False

    def get_connection_string(self):
        if self._connection_string is None:
            if self._set:
                self.raise_att_info("connection_string set as None and requested")
            else:
                self.raise_att_error("Unset connection_string requested")
        return self._connection_string

    def set_connection_string(self, value):
        self._connection_string = value
        self._set = True

    connection_string = property(get_connection_string, set_connection_string)


class FaradayServerConfigObject(ConfigSection):
    _bind_address = '0.0.0.0'
    _port = '5985'
    _secret_key = None
    _secret_key_set = False
    _websocket_port = '9000'

    def get_bind_address(self):
        if self._bind_address is None:
            self.raise_att_error("Unset bind_address requested")
        return self._bind_address

    def set_bind_address(self, value):
        self._bind_address = value

    def get_port(self):
        if self._port is None:
            self.raise_att_error("Unset port requested")
        return self._port

    def set_port(self, value):
        self._port = value

    def get_secret_key(self):
        if self._secret_key is None:
            if self._secret_key_set:
                self.raise_att_info("secret_key set as None and requested")
            else:
                self.raise_att_error("Unset secret_key requested")
        return self._secret_key

    def set_secret_key(self, value):
        self._secret_key = value
        self._secret_key_set = True

    def get_websocket_port(self):
        if self._websocket_port is None:
            self.raise_att_error("Unset websocket_port requested")
        return self._websocket_port

    def set_websocket_port(self, value):
        self._websocket_port = value

    bind_address = property(get_bind_address, set_bind_address)
    port = property(get_port, set_port)
    secret_key = property(get_secret_key, set_secret_key)
    websocket_port = property(get_websocket_port, set_websocket_port)


class LDAPConfigObject(ConfigSection):
    _admin_group = 'fadmin'
    _client_group = 'fclient'
    _disconnect_timeout = 2.0
    _domain = 'example.com'
    _domain_dn = 'DC=example,DC=com'
    _enabled = False
    _pentester_group = 'fpentester'
    _port = 389
    _server = '127.0.0.1'
    _use_ldaps = False
    _use_start_tls = False
    _use_local_roles = False
    _default_local_role = None

    def get_admin_group(self):
        if self._admin_group is None:
            self.raise_att_error("Unset admin_group requested")
        return self._admin_group

    def set_admin_group(self, value):
        self._admin_group = value

    def get_client_group(self):
        if self._client_group is None:
            self.raise_att_error("Unset client_group requested")
        return self._client_group

    def set_client_group(self, value):
        self._client_group = value

    def get_disconnect_timeout(self):
        if self._disconnect_timeout is None:
            self.raise_att_error("Unset disconnect_timeout requested")
        return self._disconnect_timeout

    def set_disconnect_timeout(self, value):
        self._disconnect_timeout = value

    def get_domain_dn(self):
        if self._domain_dn is None:
            self.raise_att_error("Unset domain_dn requested")
        return self._domain_dn

    def set_domain_dn(self, value):
        self._domain_dn = value

    def get_domain(self):
        if self._domain is None:
            self.raise_att_error("Unset domain requested")
        return self._domain

    def set_domain(self, value):
        self._domain = value

    def get_enabled(self):
        if self._enabled is None:
            self.raise_att_error("Unset enabled requested")
        return self._enabled

    def set_enabled(self, value):
        self._enabled = value

    def get_pentester_group(self):
        if self._pentester_group is None:
            self.raise_att_error("Unset pentester_group requested")
        return self._pentester_group

    def set_pentester_group(self, value):
        self._pentester_group = value

    def get_port(self):
        if self._port is None:
            self.raise_att_error("Unset port requested")
        return self._port

    def set_port(self, value):
        self._port = value

    def get_server(self):
        if self._server is None:
            self.raise_att_error("Unset server requested")
        return self._server

    def set_server(self, value):
        self._server = value

    def get_use_ldaps(self):
        if self._use_ldaps is None:
            self.raise_att_error("Unset use_ldaps requested")
        return self._use_ldaps

    def set_use_ldaps(self, value):
        self._use_ldaps = value

    def get_use_start_tls(self):
        if self._use_start_tls is None:
            self.raise_att_error("Unset use_start_tls requested")
        return self._use_start_tls

    def set_use_start_tls(self, value):
        self._use_start_tls = value

    def get_use_local_roles(self):
        if self._use_local_roles is None:
            self.raise_att_error("Unset use_local_role requested")
        return self._use_local_roles

    def set_use_local_roles(self, value):
        self._use_local_roles = value

    def get_default_local_role(self):
        if self._default_local_role is None:
            self.raise_att_info("Unset default_local_role requested")
        return self._default_local_role

    def set_default_local_role(self, value):
        self._default_local_role = value

    admin_group = property(get_admin_group, set_admin_group)
    client_group = property(get_client_group, set_client_group)
    disconnect_timeout = property(get_disconnect_timeout, set_disconnect_timeout)
    domain_dn = property(get_domain_dn, set_domain_dn)
    domain = property(get_domain, set_domain)
    enabled = property(get_enabled, set_enabled)
    pentester_group = property(get_pentester_group, set_pentester_group)
    port = property(get_port, set_port)
    server = property(get_server, set_server)
    use_ldaps = property(get_use_ldaps, set_use_ldaps)
    use_start_tls = property(get_use_start_tls, set_use_start_tls)
    use_local_roles = property(get_use_local_roles, set_use_local_roles)
    default_local_role = property(get_default_local_role,set_default_local_role)


class SSLConfigObject(ConfigSection):
    _certificate = None
    _keyfile = None
    _port = None

    def get_certificate(self):
        if self._certificate is None:
            self.raise_att_error("Unset certificate requested")
        return self._certificate

    def set_certificate(self, value):
        self._certificate = value

    def get_keyfile(self):
        if self._keyfile is None:
            self.raise_att_error("Unset keyfile requested")
        return self._keyfile

    def set_keyfile(self, value):
        self._keyfile = value

    def get_port(self):
        if self._port is None:
            self.raise_att_error("Unset port requested")
        return self._port

    def set_port(self, value):
        self._port = value

    certificate = property(get_certificate, set_certificate)
    keyfile = property(get_keyfile, set_keyfile)
    port = property(get_port, set_port)


class StorageConfigObject(ConfigSection):
    _path = None

    def get_path(self):
        if self._path is None:
            self.raise_att_info("Path set as None and requested")
        return self._path

    def set_path(self, value):
        self._path = value

    path = property(get_path, set_path)


couchdb = CouchDBConfigObject()
database = DatabaseConfigObject()
faraday_server = FaradayServerConfigObject()
ldap = LDAPConfigObject()
ssl = SSLConfigObject()
storage = StorageConfigObject()

parse_and_bind_configuration()
