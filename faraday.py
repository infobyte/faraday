#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import os
import sys
import shutil
import getpass
import argparse
import requests.exceptions

from config.configuration import getInstanceConfiguration
from config.constant import (
    CONST_USER_HOME,
    CONST_FARADAY_HOME_PATH,
    CONST_FARADAY_PLUGINS_PATH,
    CONST_FARADAY_PLUGINS_REPO_PATH,
    CONST_FARADAY_IMAGES,
    CONST_FARADAY_USER_CFG,
    CONST_FARADAY_BASE_CFG,
    CONST_USER_ZSHRC,
    CONST_FARADAY_ZSHRC,
    CONST_ZSH_PATH,
    CONST_FARADAY_ZSH_FARADAY,
    CONST_VERSION_FILE,
    CONST_REQUIREMENTS_FILE,
    CONST_FARADAY_FOLDER_LIST,
)
from utils import dependencies
from utils.logs import getLogger, setUpLogger
from utils.user_input import query_yes_no

from persistence.server import server
from persistence.server.server import is_authenticated, login_user, get_user_info

USER_HOME = os.path.expanduser(CONST_USER_HOME)
FARADAY_BASE = os.path.dirname(os.path.realpath(__file__))

FARADAY_USER_HOME = os.path.expanduser(CONST_FARADAY_HOME_PATH)

FARADAY_PLUGINS_PATH = os.path.join(FARADAY_USER_HOME, CONST_FARADAY_PLUGINS_PATH)

FARADAY_PLUGINS_BASEPATH = os.path.join(FARADAY_BASE, CONST_FARADAY_PLUGINS_REPO_PATH)

FARADAY_BASE_IMAGES = os.path.join(FARADAY_BASE, "data", CONST_FARADAY_IMAGES)

FARADAY_USER_CONFIG_XML = os.path.join(FARADAY_USER_HOME, CONST_FARADAY_USER_CFG)

FARADAY_BASE_CONFIG_XML = os.path.join(FARADAY_BASE, CONST_FARADAY_BASE_CFG)

USER_ZSHRC = os.path.expanduser(CONST_USER_ZSHRC)

FARADAY_USER_IMAGES = os.path.join(FARADAY_USER_HOME, CONST_FARADAY_IMAGES)

FARADAY_USER_ZSHRC = os.path.join(FARADAY_USER_HOME, CONST_FARADAY_ZSHRC)
FARADAY_USER_ZSH_PATH = os.path.join(FARADAY_USER_HOME, CONST_ZSH_PATH)
FARADAY_BASE_ZSH = os.path.join(FARADAY_BASE, CONST_FARADAY_ZSH_FARADAY)

FARADAY_VERSION_FILE = os.path.join(FARADAY_BASE, CONST_VERSION_FILE)
FARADAY_REQUIREMENTS_FILE = os.path.join(FARADAY_BASE, CONST_REQUIREMENTS_FILE)

REQUESTS_CA_BUNDLE_VAR = "REQUESTS_CA_BUNDLE"
FARADAY_DEFAULT_PORT_XMLRPC = 9876
FARADAY_DEFAULT_PORT_REST = 9977
FARADAY_DEFAULT_HOST = "localhost"

logger = getLogger(__name__)


def getParserArgs():
    """
    Parser setup for faraday launcher arguments.
    """

    parser = argparse.ArgumentParser(
        description="Faraday's launcher parser.",
        fromfile_prefix_chars='@')

    parser_connection = parser.add_argument_group('connection')

    parser_connection.add_argument('-n', '--hostname',
                                   action="store",
                                   dest="host",
                                   default=None,
                                   help="The hostname where both server APIs will listen (XMLRPC and RESTful). Default = localhost")

    parser_connection.add_argument('-px',
                                   '--port-xmlrpc',
                                   action="store",
                                   dest="port_xmlrpc",
                                   default=None,
                                   type=int,
                                   help="Sets the port where the API XMLRPC Server will listen. Default = 9876")

    parser_connection.add_argument('-pr',
                                   '--port-rest',
                                   action="store",
                                   dest="port_rest",
                                   default=None,
                                   type=int,
                                   help="Sets the port where the API RESTful Server will listen. Default = 9977")

    parser.add_argument('--disable-excepthook',
                        action="store_true",
                        dest="disable_excepthook",
                        default=False,
                        help="Disable the application exception hook that allows to send error reports to developers.")

    parser.add_argument('--login',
                        action="store_true",
                        dest="login",
                        default=False,
                        help="Enable prompt for authentication Database credentials")

    parser.add_argument('--dev-mode',
                        action="store_true",
                        dest="dev_mode",
                        default=False,
                        help="Enable dev mode. This will use the user config and plugin folder.")

    parser.add_argument('--cert',
                        action="store",
                        dest="cert_path",
                        default=None,
                        help="Path to the valid Faraday server certificate")

    parser.add_argument('--gui',
                        action="store",
                        dest="gui",
                        default="gtk",
                        help="Select interface to start Faraday. Supported values are 'gtk' and 'no' (no GUI at all). Defaults to GTK")

    parser.add_argument('--cli',
                        action="store_true",
                        dest="cli",
                        default=False,
                        help="Set this flag to avoid GUI and use Faraday as a CLI.")

    parser.add_argument('-w',
                        '--workspace',
                        action="store",
                        dest="workspace",
                        default=None,
                        help="Workspace to be opened")

    parser.add_argument('-r',
                        '--report',
                        action="store",
                        dest="filename",
                        default=None,
                        help="Report to be parsed by the CLI")

    parser.add_argument('-d',
                        '--debug',
                        action="store_true",
                        default=False,
                        help="Enables debug mode. Default = disabled")

    parser.add_argument('--creds-file',
                        action="store",
                        dest="creds_file",
                        default=None,
                        help="File containing user's credentials to be used in CLI mode")

    parser.add_argument('--nodeps',
                        action="store_true",
                        help='Skip dependency check')
    parser.add_argument('--keep-old', action='store_true', help='Keep old object in CLI mode if Faraday find a conflict')
    parser.add_argument('--keep-new', action='store_true', help='Keep new object in CLI mode if Faraday find a conflict (DEFAULT ACTION)')

    f = open(FARADAY_VERSION_FILE)
    f_version = f.read().strip()

    parser.add_argument('-v', '--version', action='version',
                        version='Faraday v{version}'.format(version=f_version))

    return parser.parse_args()


def check_dependencies_or_exit():
    """
    Dependency resolver based on a previously specified CONST_REQUIREMENTS_FILE.
    Currently checks a list of dependencies from a file and exits if they are not met.
    """

    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(requirements_file=FARADAY_REQUIREMENTS_FILE)

    logger.info("Checking dependencies...")

    if conflict_deps:
        logger.info("Some dependencies are old. Update them with \"pip install -r requirements_server.txt -U\"")

    if missing_deps:

        install_deps = query_yes_no("Do you want to install them?", default="no")

        if install_deps:
            dependencies.install_packages(missing_deps)
            logger.info("Dependencies installed. Please launch Faraday Server again.")
            sys.exit(0)
        else:
            logger.error("Dependencies not met. Please refer to the documentation in order to install them. [%s]",
                         ", ".join(missing_deps))
            sys.exit(1)

    logger.info("Dependencies met")

def setConf():
    """
    User configuration management and instantiation.
    Setting framework configuration based either on previously user saved
    settings or default ones.
    """

    logger.info("Setting configuration.")

    CONF = getInstanceConfiguration()
    CONF.setDebugStatus(args.debug)

    host = CONF.getApiConInfoHost() if str(CONF.getApiConInfoHost()) != "None" else FARADAY_DEFAULT_HOST
    port_xmlrpc = CONF.getApiConInfoPort() if str(CONF.getApiConInfoPort()) != "None" else FARADAY_DEFAULT_PORT_XMLRPC
    port_rest = CONF.getApiRestfulConInfoPort() if str(
        CONF.getApiRestfulConInfoPort()) != "None" else FARADAY_DEFAULT_PORT_REST

    host = args.host if args.host else host
    port_xmlrpc = args.port_xmlrpc if args.port_xmlrpc else port_xmlrpc
    port_rest = args.port_rest if args.port_rest else port_rest

    CONF.setApiConInfoHost(host)
    CONF.setApiConInfoPort(port_xmlrpc)
    CONF.setApiRestfulConInfoPort(port_rest)


def startFaraday():
    """Application startup.

    Starts a MainApplication with the previously parsed arguments, and handles
    a profiler if requested.

    Returns application status.

    """
    from model.application import MainApplication

    logger.info("All done. Opening environment.")
    # TODO: Handle args in CONF and send only necessary ones.

    main_app = MainApplication(args)

    if not args.disable_excepthook:
        logger.info("Main application ExceptHook enabled.")
        main_app.enableExceptHook()

    logger.info("Starting main application.")
    start = main_app.start

    from colorama import Fore, Back, Style
    serverURL = getInstanceConfiguration().getServerURI()
    if serverURL:
        url = "%s/_ui" % serverURL
        print(Fore.WHITE + Style.BRIGHT + "\n* " + "Faraday UI is ready")
        print(
            Fore.WHITE + Style.BRIGHT + "Point your browser to: \n[%s]" % url)

    print(Fore.RESET + Back.RESET + Style.RESET_ALL)

    exit_status = start()

    return exit_status


def setupPlugins(dev_mode=False):
    """
    Checks and handles Faraday's plugin status.

    When dev_mode is True, the user enters in development mode and the plugins
    will be replaced with the latest ones.

    Otherwise, it checks if the plugin folders exists or not, and creates it
    with its content.

    TODO: When dependencies are not satisfied ask user if he wants to try and
    run faraday with a inestability warning.
    """

    if dev_mode:
        logger.warning("Running under plugin development mode!")
        logger.warning("Using user plugins folder")
    else:
        if os.path.isdir(FARADAY_PLUGINS_PATH):
            logger.info("Removing old plugins folder.")
            shutil.rmtree(FARADAY_PLUGINS_PATH)
        else:
            logger.info("No plugins folder detected. Creating new one.")

        shutil.copytree(FARADAY_PLUGINS_BASEPATH, FARADAY_PLUGINS_PATH)


def setupZSH():
    """
    Checks and handles Faraday's integration with ZSH.

    If the user has a .zshrc file, it gets copied and integrated with
    faraday's zsh plugin.
    """

    if os.path.isfile(USER_ZSHRC):
        shutil.copy(USER_ZSHRC, FARADAY_USER_ZSHRC)
    else:
        open(FARADAY_USER_ZSHRC, 'w').close()

    with open(FARADAY_USER_ZSHRC, "r+") as f:
        content = f.read()
        f.seek(0, 0)
        f.write('ZDOTDIR=$OLDZDOTDIR' + '\n' + content)
    with open(FARADAY_USER_ZSHRC, "a") as f:
        f.write("source \"%s\"" % FARADAY_BASE_ZSH)
    shutil.copy(FARADAY_BASE_ZSH, FARADAY_USER_ZSH_PATH)


def setupXMLConfig():
    """
    Checks user configuration file status.

    If there is no custom config the default one will be copied as a default.
    """

    if not os.path.isfile(FARADAY_USER_CONFIG_XML):
        logger.info("Copying default configuration from project.")
        shutil.copy(FARADAY_BASE_CONFIG_XML, FARADAY_USER_CONFIG_XML)
    else:
        logger.info("Using custom user configuration.")


def setupImages():
    """
    Copy png icons
    """
    if os.path.exists(FARADAY_USER_IMAGES):
        shutil.rmtree(FARADAY_USER_IMAGES)
    shutil.copytree(FARADAY_BASE_IMAGES, FARADAY_USER_IMAGES)


def checkConfiguration(gui_type):
    """
    Checks if the environment is ready to run Faraday.

    Checks different environment requirements and sets them before starting
    Faraday. This includes checking for plugin folders, libraries,
    and ZSH integration.
    """
    logger.info("Checking configuration.")
    logger.info("Setting up plugins.")
    setupPlugins(args.dev_mode)
    logger.info("Setting up ZSH integration.")
    setupZSH()
    logger.info("Setting up user configuration.")
    setupXMLConfig()
    logger.info("Setting up icons for GTK interface.")
    setupImages()


def setupFolders(folderlist):
    """
    Checks if a list of folders exists and creates them otherwise.
    """

    for folder in folderlist:
        fp_folder = os.path.join(FARADAY_USER_HOME, folder)
        checkFolder(fp_folder)


def checkFolder(folder):
    """
    Checks whether a folder exists and creates it if it doesn't.
    """

    if not os.path.isdir(folder):
        if logger:
            logger.info("Creating %s" % folder)
        os.makedirs(folder)


def printBanner():
    """
    Prints Faraday's ascii banner.
    """
    from colorama import Fore, Back, Style
    print (Fore.RED + """
  _____                           .___
_/ ____\_____  ____________     __| _/_____   ___.__.
\   __\ \__  \ \_  __ \__  \   / __ | \__  \ <   |  |
 |  |    / __ \_|  | \// __ \_/ /_/ |  / __ \_\___  |
 |__|   (____  /|__|  (____  /\____ | (____  // ____|
             \/            \/      \/      \/ \/
    """)

    print(Fore.WHITE + Back.RED + Style.BRIGHT + "[*[       Open Source Penetration Test IDE       ]*]")
    print(Back.RESET + "            Where pwnage goes multiplayer")
    print(Fore.RESET + Back.RESET + Style.RESET_ALL)
    logger.info("Starting Faraday IDE.")


def checkUpdates():
    import requests
    uri = getInstanceConfiguration().getUpdatesUri()
    resp = u"OK"
    try:
        f = open(FARADAY_VERSION_FILE)

        getInstanceConfiguration().setVersion(f.read().strip())
        getInstanceConfiguration().setAppname("Faraday - Penetration Test IDE Community")
        parameter = {"version": getInstanceConfiguration().getVersion()}

        f.close()
        resp = requests.get(uri, params=parameter, timeout=1, verify=True)
        resp = resp.text.strip()
    except Exception as e:
        logger.error(e)
    version = getInstanceConfiguration().getVersion()
    if 'b' in version.split("+")[0]:
        return
    if not resp == u'OK':
        logger.info("You have available updates. Run ./faraday.py --update to catchup!")
    else:
        logger.info("No updates available, enjoy Faraday.")


def check_faraday_version():
    try:
        server.check_faraday_version()
    except RuntimeError:
        getLogger("launcher").error(
            "The server is running a different Faraday version than the client you are running. Version numbers must match!")
        sys.exit(2)


def try_login_user(server_uri, api_username, api_password):
    
    try:
        session_cookie = login_user(server_uri, api_username, api_password)
        return session_cookie
    except requests.exceptions.SSLError:
        print("SSL certificate validation failed.\nYou can use the --cert option in Faraday to set the path of the cert")
        sys.exit(-1)
    except requests.exceptions.MissingSchema:
        print("The Faraday Server URL is incorrect, please try again.")
        sys.exit(-2)


def doLoginLoop(force_login=False):
    """
    Sets the username and passwords from the command line.
    If --login flag is set then username and password is set
    """

    try:

        CONF = getInstanceConfiguration()
        old_server_url = CONF.getAPIUrl()
        api_username = CONF.getAPIUsername()
        api_password = CONF.getAPIPassword()
        if old_server_url and api_username and api_password and not force_login:
            return

        if old_server_url is None:
            new_server_url = raw_input(
            "\nPlease enter the Faraday Server URL (Press enter for http://localhost:5985): ") or "http://localhost:5985"
        else:
            new_server_url = raw_input(
                "\nPlease enter the Faraday Server URL (Press enter for last used: {}): ".format(old_server_url)) or old_server_url
        
        CONF.setAPIUrl(new_server_url)

        print("""\nTo login please provide your valid Faraday credentials.\nYou have 3 attempts.""")

        for attempt in range(1, 4):

            api_username = raw_input("Username (press enter for faraday): ") or "faraday"
            api_password = getpass.getpass('Password: ')

            session_cookie = try_login_user(new_server_url, api_username, api_password)

            if session_cookie:

                CONF.setAPIUsername(api_username)
                CONF.setAPIPassword(api_password)
                CONF.setDBSessionCookies(session_cookie)
                CONF.saveConfig()

                user_info = get_user_info()
                if (user_info is None) or (not user_info) or ('username' not in user_info):
                    print('Login failed, please try again. You have %d more attempts' % (3 - attempt))
                    continue

                logger.info('Login successful: {0}'.format(api_username))
                break

            print('Login failed, please try again. You have %d more attempts' % (3 - attempt))

        else:
            logger.fatal('Invalid credentials, 3 attempts failed. Quitting Faraday...')
            sys.exit(-1)

    except KeyboardInterrupt:
        sys.exit(0)


def login(forced_login):

    CONF = getInstanceConfiguration()
    server_uri = CONF.getServerURI()
    api_username = CONF.getAPIUsername()
    api_password = CONF.getAPIPassword()

    if forced_login:
        doLoginLoop(forced_login)
        return

    if server_uri and api_username and api_password:

        session_cookie = try_login_user(server_uri, api_username, api_password)

        if session_cookie:
            CONF.setDBSessionCookies(session_cookie)
            logger.info('Login successful: {0}'.format(api_username))
            return

    doLoginLoop()


def main():
    """
    Main function for launcher.
    """
    os.chdir(FARADAY_BASE)

    global logger, args

    logger = getLogger("launcher")
    args = getParserArgs()
    setupFolders(CONST_FARADAY_FOLDER_LIST)
    setUpLogger(args.debug)
    if not args.nodeps:
        check_dependencies_or_exit()
    printBanner()
    if args.cert_path:
        os.environ[REQUESTS_CA_BUNDLE_VAR] = args.cert_path
    checkConfiguration(args.gui)
    setConf()
    login(args.login)
    check_faraday_version()
    checkUpdates()
    startFaraday()


if __name__ == '__main__':
    main()
