import ConfigParser
import logging
import os, shutil
import errno

DEBUG = True
LOGGING_LEVEL = logging.DEBUG
FARADAY_BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

DEFAULT_CONFIG_FILE = os.path.join(FARADAY_BASE, 'server/default.ini')
LOCAL_CONFIG_FILE = os.path.expanduser('~/.faraday/config/server.ini')

CONFIG_FILES = [ DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE ]

def copy_default_config_to_local():
    if not os.path.exists(LOCAL_CONFIG_FILE):
        # Create directory if it doesn't exist
        try:
            os.makedirs(os.path.dirname(LOCAL_CONFIG_FILE))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        # Copy default config file into faraday local config
        shutil.copyfile(DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE)

        print("[!] Local Faraday-Server configuration created in %s" % LOCAL_CONFIG_FILE)

def parse_and_bind_configuration():
    # Load configuration from files declared above and put them
    # on this module's namespace for convenient access
    __parser = ConfigParser.SafeConfigParser()
    __parser.read(CONFIG_FILES)

    class ConfigSection(object):
        def __init__(self, name, parser):
            self.__name = name
            self.__parser = parser

        def __getattr__(self, option_name):
            return self.__parser.get(self.__name, option_name)

    for section in __parser.sections():
        globals()[section] = ConfigSection(section, __parser)

copy_default_config_to_local()
parse_and_bind_configuration()

