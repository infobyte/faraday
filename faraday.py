#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

# TODO:
# - Handle requirements dinamically?
# - Additionally parse arguments from file.


import os
import sys
import shutil
import argparse
import platform
import subprocess
import pip

from utils.logs import getLogger, setUpLogger
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/external_libs/lib/python2.7/dist-packages')
from config.configuration import getInstanceConfiguration
from config.globals import *
from utils.profilehooks import profile



USER_HOME = os.path.expanduser(CONST_USER_HOME)
FARADAY_BASE = os.path.dirname(os.path.realpath(__file__))
QTDIR=os.path.join(FARADAY_BASE, 'external_libs', 'qt')

FARADAY_USER_HOME = os.path.expanduser(CONST_FARADAY_HOME_PATH)
FARADAY_PLUGINS_PATH = os.path.join(FARADAY_USER_HOME,
                        CONST_FARADAY_PLUGINS_PATH)
FARADAY_PLUGINS_BASEPATH = os.path.join(FARADAY_BASE,
                            CONST_FARADAY_PLUGINS_REPO_PATH)

FARADAY_BASE_LIB_HELPERS = os.path.join(FARADAY_BASE,
                            CONST_FARADAY_LIB_HELPERS)

FARADAY_BASE_IMAGES = os.path.join(FARADAY_BASE, "data",
                            CONST_FARADAY_IMAGES)

FARADAY_USER_CONFIG_XML = os.path.join(FARADAY_USER_HOME,
                            CONST_FARADAY_USER_CFG)
FARADAY_BASE_CONFIG_XML = os.path.join(FARADAY_BASE,
                            CONST_FARADAY_BASE_CFG)

USER_ZSHRC = os.path.expanduser(CONST_USER_ZSHRC)
FARADAY_USER_IMAGES = os.path.join(FARADAY_USER_HOME,
                            CONST_FARADAY_IMAGES)
FARADAY_USER_ZSHRC = os.path.join(FARADAY_USER_HOME, CONST_FARADAY_ZSHRC)
FARADAY_USER_ZSH_PATH = os.path.join(FARADAY_USER_HOME, CONST_ZSH_PATH)
FARADAY_BASE_ZSH = os.path.join(FARADAY_BASE, CONST_FARADAY_ZSH_FARADAY)
FARADAY_BASE_ZSH_PLUGIN = os.path.join(FARADAY_BASE,
                            CONST_FARADAY_ZSH_PLUGIN)

USER_QT = os.path.expanduser(CONST_USER_QT_PATH)
USER_QTRC = os.path.expanduser(CONST_USER_QTRC_PATH)
USER_QTRCBAK = os.path.expanduser(CONST_USER_QTRC_BACKUP)
FARADAY_QTRC = os.path.join(FARADAY_BASE, CONST_FARADAY_QTRC_PATH)
FARADAY_QTRCBAK = os.path.expanduser(CONST_FARADAY_QTRC_BACKUP)
CONST_VERSION_FILE = os.path.join(FARADAY_BASE,"VERSION")

def getParserArgs():
    """Parser setup for faraday launcher arguments.

    """

    parser = argparse.ArgumentParser(
        description="Faraday's launcher parser.",
        fromfile_prefix_chars='@')

    parser_connection = parser.add_argument_group('connection')
    parser_profile = parser.add_argument_group('profiling')
    parser_gui_ex = parser.add_mutually_exclusive_group()

    parser_connection.add_argument('-n', '--hostname', action="store",
        dest="host",
        default="localhost",
        help="The hostname where api XMLRPCServer will listen. \
        Default = localhost")

    parser_connection.add_argument('-p', '--port', action="store", dest="port",
        default=9876, type=int,
        help="Sets the port where api XMLRPCServer will listen. Default = 9876")

    parser.add_argument('-d', '--debug', action="store_true", dest="debug",
        default=False,
        help="Enables debug mode. Default = disabled")

    parser_profile.add_argument('--profile', action="store_true",
        dest="profile",
        default=False,
        help="Enables application profiling. When this option is used \
         --profile-output and --profile-depth can also be used. \
         Default = disabled")

    parser_profile.add_argument('--profile-output', action="store",
        dest="profile_output",
        default=None,
        help="Sets the profile output filename. If no value is provided, \
        standard output will be used")

    parser_profile.add_argument('--profile-depth', action="store",
        dest="profile_depth", type=int,
        default=500,
        help="Sets the profile number of entries (depth). Default = 500")

    parser.add_argument('--disable-excepthook', action="store_true",
        dest="disable_excepthook",
        default=False,
        help="Disable the application exception hook that allows to send error \
        reports to developers.")

    parser.add_argument('--disable-login', action="store_true",
        dest="disable_login",
        default=False,
        help="Disable the auth splash screen.")

    parser.add_argument('--dev-mode', action="store_true", dest="dev_mode",
        default=False,
        help="Enable dev mode. This will use the user config and plugin folder.")

    parser.add_argument('--ignore-deps', action="store_true",
        dest="ignore_deps",
        default=False,
        help="Ignore python dependencies resolution.")

    parser.add_argument('--update', action="store_true", dest="update",
        default=False,
        help="Update Faraday IDE.")

    parser_gui_ex.add_argument('--gui', action="store", dest="gui",
        default="qt3",
        help="Select interface to start faraday. Default = qt3")

    parser_gui_ex.add_argument('--cli', '--console', action="store_true",
        dest="cli",
        default="false",
        help="Set this flag to avoid gui and use faraday as a cli.")

    #args = parser.parse_args(['@parser_args.cfg'])
    return parser.parse_args()

def query_user_bool(question, default=True):
    """Returns a boolean based on user input.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be True (the default), False or None (meaning
        an answer is required of the user).

    The "answer" return value is one of True or False.

    """

    valid_yes_ans = ["yes", "y"]
    valid_no_ans = ["no", "n"]

    if default is None:
        prompt = " [y/n] "
    elif default:
        prompt = " [Y/n] "
    else:
        prompt = " [y/N] "

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()

        if default is not None and choice == '':
            return default

        if choice in valid_yes_ans:
            return True

        if choice in valid_no_ans:
            return False

        sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")


def checkDependencies():
    """Dependency resolver based on a previously specified CONST_REQUIREMENTS_FILE.

    Currently checks a list of dependencies from a file and asks for user
    confirmation on whether to install it with a specific version or not.

    """

    if not args.ignore_deps:

        modules = []
        f = open(CONST_REQUIREMENTS_FILE)
        for line in f:
            if not line.find('#'):
                break
            else:
                modules.append([line[:line.index('=')], (line[line.index('=')+2:]).strip()])
        f.close()

        pip_dist = [dist.project_name.lower() for dist in pip.get_installed_distributions()]

        for module in modules:
            if module[0].lower() not in pip_dist:
                try:
                    __import__(module[0])
                except ImportError:
                    if query_user_bool("Missing module %s." \
                        " Do you wish to install it?" % module[0]):
                        pip.main(['install', "%s==%s" %
                                 (module[0], module[1]), '--user'])

                    else:
                        return False

    return True


def startProfiler(app, output, depth):
    """Profiler handler.

    Will start a profiler on the given application in a specified output with
    a custom depth.

    TODO: Check if it's necessary to add a dummy in case o failed import.

    """

    logger.warning("[!] Faraday will be started with a profiler attached." \
    "Performance may be affected.")

    start = profile(app,
            filename=output,
            entries=depth)
    return start

def setConf():
    """User configuration management and instantiation.

    Setting framework configuration based either on previously user saved
    settings or default ones.

    """

    logger.info("Setting configuration.")

    CONF = getInstanceConfiguration()
    CONF.setDebugStatus(args.debug)
    if args.host != 'localhost':
        CONF.setApiConInfoHost(args.host)
    if args.port != 9876:
        CONF.setApiConInfoPort(args.port)
    CONF.setAuth(args.disable_login)


def startFaraday():
    """Application startup.

    Starts a MainApplication with the previously parsed arguments, and handles
    a profiler if requested.

    Returns application status.

    """
    from model.application import MainApplication

    logger.info("All done. Opening environment.")
    #TODO: Handle args in CONF and send only necessary ones.
    # Force OSX to run no gui
    if sys.platform == "darwin":
        args.gui = "no-gui"

    main_app = MainApplication(args)

    if not args.disable_excepthook:
            logger.warning("Main application ExceptHook enabled.")
            main_app.enableExceptHook()

    if args.profile:
        logger.info("Starting main application with profiler.")
        start = startProfiler(
                main_app.start,
                args.profile_output,
                args.profile_depth)
    else:
        logger.info("Starting main application.")
        start = main_app.start
    from colorama import Fore, Back, Style
    import string
    couchURL = getInstanceConfiguration().getCouchURI()
    if couchURL:
        url = "%s/reports/_design/reports/index.html" % couchURL
        print(Fore.WHITE + Style.BRIGHT + \
            "\n*" + string.center("faraday ui is ready", 53 - 6) )
        print(Fore.WHITE + Style.BRIGHT + \
                """Make sure you got couchdb up and running.\nIf couchdb is up, point your browser to: \n[%s]""" % url) 
    else:
        print(Fore.WHITE + Style.BRIGHT + \
                """Please config Couchdb for fancy HTML5 Dashboard""") 

    print(Fore.RESET + Back.RESET + Style.RESET_ALL)

    exit_status = start()

    return exit_status

def setupPlugins(dev_mode=False):
    """Checks and handles Faraday's plugin status.

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
            logger.info("Removing old plugins folder")
            shutil.rmtree(FARADAY_PLUGINS_PATH)
        else:
            logger.info("No plugins folder detected. Creating new one.")

        shutil.copytree(FARADAY_PLUGINS_BASEPATH, FARADAY_PLUGINS_PATH)

def setupQtrc():
    """Cheks and handles QT configuration file.

    Existing qtrc files will be backed up and faraday qtrc will be set.

    """
    from ctypes import cdll
    try:
        import qt
    except:
        try:
            cdll.LoadLibrary(os.path.join(QTDIR, 'lib', 'libqt.so'))
            cdll.LoadLibrary(os.path.join(QTDIR, 'lib', 'libqui.so'))
        except:
            pass

def setupZSH():
    """Cheks and handles Faraday's integration with ZSH.

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
        f.write("source %s" % FARADAY_BASE_ZSH)
    shutil.copy(FARADAY_BASE_ZSH, FARADAY_USER_ZSH_PATH)
    shutil.copy(FARADAY_BASE_ZSH_PLUGIN, FARADAY_USER_ZSH_PATH)

def setupXMLConfig():
    """Checks user configuration file status.

    If there is no custom config the default one will be copied as a default.
    """

    if not os.path.isfile(FARADAY_USER_CONFIG_XML):
        logger.info("Copying default configuration from project.")
        shutil.copy(FARADAY_BASE_CONFIG_XML, FARADAY_USER_CONFIG_XML)
    else:
        logger.info("Using custom user configuration.")

def setupLibs():
    """Checks ELF libraries status."

    Right now it only looks for the right helpers.so from the base path based on
    system platform and architecture, and creates a symbolic link to it inside
    the same folder.

    """

    arch = platform.machine()
    helpers = FARADAY_BASE_LIB_HELPERS
    if sys.platform == "linux" or sys.platform == "linux2":
        if arch == "amd64" or arch == "x86_64":
            logger.info("x86_64 linux detected.")
            helpers += ".amd64"
        elif arch == "i686" or arch == "i386":
            logger.info("i386/686 linux detected.")
            helpers += ".i386"
        else:
            logger.fatal("Linux architecture could not be determined.")
            exit()
    elif sys.platform == "darwin":
        logger.info("OS X detected.")
        helpers += ".darwin"
    else:
        logger.fatal("Plaftorm not supported yet.")
        exit()

    if os.path.isfile(FARADAY_BASE_LIB_HELPERS):
        os.remove(FARADAY_BASE_LIB_HELPERS)

    subprocess.call(['ln', '-s', helpers, FARADAY_BASE_LIB_HELPERS])

def setupImages():
    """ Copy png icons
    """
    if os.path.exists(FARADAY_USER_IMAGES):
        shutil.rmtree(FARADAY_USER_IMAGES)
    shutil.copytree(FARADAY_BASE_IMAGES, FARADAY_USER_IMAGES)

def checkConfiguration():
    """Checks if the environment is ready to run Faraday.

    Checks different environment requirements and sets them before starting
    Faraday. This includes checking for plugin folders, libraries, QT
    configuration and ZSH integration.
    """

    logger.info("Checking configuration.")
    logger.info("Setting up plugins.")
    setupPlugins(args.dev_mode)
    logger.info("Setting up folders.")
    setupFolders(CONST_FARADAY_FOLDER_LIST)
    logger.info("Setting up Qt configuration.")
    setupQtrc()
    logger.info("Setting up ZSH integration.")
    setupZSH()
    logger.info("Setting up  user configuration.")
    setupXMLConfig()
    logger.info("Setting up libraries.")
    setupLibs()
    logger.info("Setting up icons for QT interface.")
    setupImages()

def setupFolders(folderlist):
    """Checks if a list of folders exists and creates them otherwise.

    """

    for folder in folderlist:
        fp_folder = os.path.join(FARADAY_USER_HOME, folder)
        checkFolder(fp_folder)

def checkFolder(folder):
    """Checks whether a folder exists and creates it if it doesn't.

    """

    if not os.path.isdir(folder):
        logger.info("Creating %s" % folder)
        os.mkdir(folder)

def printBanner():
    """Prints Faraday's ascii banner.

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

    print(Fore.WHITE + Back.RED + Style.BRIGHT + \
    "[*[       Open Source Penetration Test IDE       ]*]")
    print(Back.RESET + "            Where pwnage goes multiplayer")
    print(Fore.RESET + Back.RESET + Style.RESET_ALL)
    logger.info("Starting Faraday IDE.")

def update():
    """Updates Faraday IDE.

    Deletes every .pyc file and does a git pull to the official repository.

    """
    if args.update:
        from updates.updater import Updater
        Updater().doUpdates()
        logger.info("Update process finished with no errors")
        logger.info("Faraday will start now.")

def checkUpdates(): 
    import requests
    uri = getInstanceConfiguration().getUpdatesUri() 
    resp = u"OK"
    try:
        f = open(CONST_VERSION_FILE)

        getInstanceConfiguration().setVersion(f.read().strip())
        getInstanceConfiguration().setAppname("Faraday - Penetration Test IDE Community")
        parameter = {"version": getInstanceConfiguration().getVersion()}

        f.close
        resp = requests.get(uri, params=parameter, timeout=1, verify=True)
        resp = resp.text.strip()
    except Exception as e:
        logger.error(e)
    if not resp == u'OK':
        logger.info("You have available updates. Run ./faraday.py --update to catchup!")
    else:
        logger.info("No updates available, enjoy Faraday")


def init():
    """Initializes what is needed before starting.

    For now we initialize logger and arguments setup.

    """

    global args
    global logger

    args = getParserArgs()
    logger = getLogger("launcher")

def main():
    """Main.

    Main function for launcher.

    """

    init()
    if checkDependencies():
        printBanner()
        logger.info("Dependencies met.")
        checkConfiguration()
        setConf()
        setUpLogger()
        update()
        checkUpdates()
        startFaraday()
    else:
        logger.error("Dependencies not met. Unable to start Faraday.")


if __name__ == '__main__':
    main()
