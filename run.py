#!/usr/bin/env python2
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

# TODO:
# - Handle requirements dinamically.
# - Additionally parse arguments from file.
# - Add logger.
# - Colorize!?

import os
import sys
import shutil
import argparse
import subprocess
import platform
from colorama import Fore, Back, Style

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__))) # Necessary?
from config.configuration import getInstanceConfiguration
from model.application import MainApplication
from utils.profilehooks import profile


# Load globals from config file?
CONST_REQUIREMENTS_FILE = 'requirements.txt'
CONST_FARADAY_HOME_PATH = '~/.faraday'
CONST_FARADAY_PLUGINS_PATH = 'plugins'
CONST_FARADAY_PLUGINS_REPO_PATH = 'plugins/repo'
CONST_FARADAY_QTRC_PATH = 'deps/qtrc'
CONST_FARADAY_FOLDER_LIST = [ "config", "data", "images", 
                        "persistence", "plugins",
                        "report", "temp", "zsh" ]


CONST_USER_QTRC_PATH = '~/.qt/qtrc'
CONST_USER_QTRC_BACKUP = '~/.qt/.qtrc_original.bak'
CONST_FARADAY_QTRC_BACKUP = '~/.qt/.qtrc_faraday.bak'
CONST_FARADAY_ZSHRC = "zsh/.zshrc"
CONST_FARADAY_ZSH_FARADAY = "zsh/faraday.zsh"
CONST_FARADAY_ZSH_PLUGIN = "zsh/plugin_controller_client.py"
CONST_FARADAY_BASE_CFG = "config/default.xml"
CONST_FARADAY_USER_CFG = "config/config.xml"
CONST_FARADAY_LIB_HELPERS = "shell/core/_helpers.so"

CONST_USER_HOME = "~"
CONST_USER_ZSHRC = "~/.zshrc"
CONST_ZSH_PATH = "zsh"


user_home = os.path.expanduser(CONST_USER_HOME)
faraday_base = os.path.dirname(os.path.realpath(__file__))

faraday_user_home = os.path.expanduser(CONST_FARADAY_HOME_PATH)
faraday_plugins_path = os.path.join(faraday_user_home, CONST_FARADAY_PLUGINS_PATH)
faraday_plugins_basepath = os.path.join(faraday_base, 
                            CONST_FARADAY_PLUGINS_REPO_PATH)

faraday_base_lib_helpers = os.path.join(faraday_base, CONST_FARADAY_LIB_HELPERS)
faraday_user_config_xml = os.path.join(faraday_user_home, CONST_FARADAY_USER_CFG)
faraday_base_config_xml = os.path.join(faraday_base, CONST_FARADAY_BASE_CFG)

user_zshrc = os.path.expanduser(CONST_USER_ZSHRC)
faraday_user_zshrc = os.path.join(faraday_user_home, CONST_FARADAY_ZSHRC)
faraday_user_zsh_path = os.path.join(faraday_user_home, CONST_ZSH_PATH)
faraday_base_zsh = os.path.join(faraday_base, CONST_FARADAY_ZSH_FARADAY)
faraday_base_zsh_plugin = os.path.join(faraday_base, CONST_FARADAY_ZSH_PLUGIN)

user_qtrc = os.path.expanduser(CONST_USER_QTRC_PATH)
user_qtrcbak = os.path.expanduser(CONST_USER_QTRC_BACKUP)
faraday_qtrc = os.path.join(faraday_base, CONST_FARADAY_QTRC_PATH)
faraday_qtrcbak = os.path.expanduser(CONST_FARADAY_QTRC_BACKUP)




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
        help="Enable dev mode. This will reset config and plugin folders.")

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

    modules = []
    f = open(CONST_REQUIREMENTS_FILE)
    for line in f:
        if line.find('#'):
            modules.append([line[:line.index('=')], (line[line.index('=')+2:]).strip()])
    f.close()

    for module in modules:
        try:
            __import__(module[0])
        except ImportError:          
            if query_user_bool("Missing module %s." \
                " Do you wish to install it?" % module[0]):
                #print "pip2 install %s==%s" % (module[0], module[1])
                subprocess.call(["pip2", "install", "%s==%s" %
                                (module[0], module[1])])
                
            else:
                return False
    return True

def startProfiler(app, output, depth):
    """Profiler handler.

    Will start a profiler on the given application in a specified output with
    a custom depth.

    TODO: Check if it's necessary to add a dummy in case o failed import.

    """
    print "[!] Faraday will be started with a profiler attached." \
    "Performance may be affected."

    start = profile(app,
            filename=output,
            entries=depth)
    return start

def setConf():
    """User configuration management and instantiation.

    Setting framework configuration based either on previously user saved
    settings or default ones.

    """

    global args # TODO: Handle as a class attribute

    args = getParserArgs()
    CONF = getInstanceConfiguration()
    CONF.setDebugStatus(args.debug)
    CONF.setApiConInfo(args.host, args.port)
    CONF.setAuth(args.disable_login)


def startFaraday():
    """Application startup.

    Starts a MainApplication with the previously parsed arguments, and handles
    a profiler if requested.

    Returns application status.

    """

    #TODO: Handle args in CONF and send only necessary ones.
    main_app = MainApplication(args)

    if not args.disable_excepthook:
            main_app.enableExceptHook()

    if args.profile:
        start = startProfiler(
                main_app.start, 
                args.profile_output, 
                args.profile_depth)
    else:
        start = main_app.start

    # TODO: This should be outside setConf in order to retrieve exit status.

    exit_status = start()
    restoreQtrc()

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

    if not dev_mode and os.path.isdir(faraday_plugins_path):
        print "[*] Plugins in place."
    else:
        if dev_mode:
            print "[*] Running under plugin development mode!"
            print "[-] Deleting old user directory: %s" % faraday_plugins_path
            shutil.rmtree(faraday_plugins_path)
        else:
            print "[!] No plugin folder detected."

        print "[+] Creating user directory: %s" % faraday_plugins_path
        shutil.copytree(faraday_plugins_basepath, faraday_plugins_path)
        print "[*] Plugins succesfully loaded."

def setupQtrc():
    """Cheks and handles QT configuration file.

    Existing qtrc files will be backed up and faraday qtrc will be set.

    """
    print "[*] QT configuration startup."
    if os.path.isfile(user_qtrc):
        print "[!] User QT config exists. Backing it up."
        shutil.copy2(user_qtrc, user_qtrcbak)

    if os.path.isfile(faraday_qtrcbak):
        print "[+] Faraday QT config exists. Setting it up."
        shutil.copy(faraday_qtrcbak, user_qtrc)
    else:
        print "[+] Setting up faraday's base QT config."
        shutil.copy(faraday_qtrc, user_qtrc)

    print "[*] QT configuration done."

def restoreQtrc():
    """Restores user qtrc.

    After exiting faraday the original qtrc is restored.

    """
    print "[!] Backing up Faraday's QT config."
    shutil.copy2(user_qtrc, faraday_qtrcbak)

    if os.path.isfile(user_qtrcbak):
        print "[!] Setting old user QT config."
        shutil.copy(user_qtrcbak, user_qtrc)


def setupZSH():
    """Cheks and handles Faraday's integration with ZSH.

    If the user has a .zshrc file, it gets copied and integrated with 
    faraday's zsh plugin.

    """

    print "[*] Setting up ZSH."
    if os.path.isfile(user_zshrc):
        shutil.copy(user_zshrc, faraday_user_zshrc)
    else:
        subprocess.call['touch', faraday_user_zshrc]

    subprocess.call(['sed', '-i', '1iZDOTDIR=$OLDZDOTDIR', faraday_user_zshrc])
    with open(faraday_user_zshrc, "a") as f:
        f.write("source %s" % faraday_base_zsh)
    shutil.copy(faraday_base_zsh, faraday_user_zsh_path)
    shutil.copy(faraday_base_zsh_plugin, faraday_user_zsh_path)

def setupXMLConfig():
    """Checks user configuration file status.

    If there is no custom config the default one will be copied as a default.
    """
    if not os.path.isfile(faraday_user_config_xml):
        print "[*] Copying default configuration from project"
        print faraday_base_config_xml, faraday_user_config_xml
        shutil.copy(faraday_base_config_xml, faraday_user_config_xml)
    else:
        print "[*] Using custom user configuration"

def setupLibs():
    """Checks ELF libraries status."

    Right now it only looks for the right helpers.so from the base path based on
    system platform and architecture, and creates a symbolic link to it inside
    the same folder.

    """
    arch = platform.machine()
    helpers = faraday_base_lib_helpers
    print "[*] Setting _helpers.so"
    if sys.platform == "linux" or sys.platform == "linux2":
        if arch == "amd64" or arch == "x86_64":
            print "[!] x86_64 linux detected."
            helpers += ".amd64"
        elif arch == "i686" or arch == "i386":
            print "[!] i386/686 linux detected."
            helpers += ".i386"
        else:
            print "[!] Linux arch could not be determined."
            exit()
    elif sys.platform == "darwin":
        print "[!] OS X detected."
        helpers += "darwin"
    else:
        print "[!] Seems like your platform is not supported yet."
        exit()

    if os.path.isfile(faraday_base_lib_helpers):
        "[-] Removing old symbolic link in case faraday was moved."
        os.remove(faraday_base_lib_helpers)

    print "[+] Creating new symbolic link." 
    subprocess.call(['ln', '-s', helpers, faraday_base_lib_helpers])
    print "[*] _helpers.so setup succesful"

def checkConfiguration():
    """Checks if the environment is ready to run Faraday.

    Checks different environment requirements and sets them before starting
    Faraday. This includes checking for plugin folders, libraries, QT 
    configuration and ZSH integration.
    """

    setupPlugins(args.dev_mode)
    setupFolders(CONST_FARADAY_FOLDER_LIST)
    setupQtrc()
    setupZSH()
    setupXMLConfig()
    setupLibs()

def setupFolders(folderlist):
    """Checks if a list of folders exists and creates them otherwise.

    """
    for folder in folderlist:
        fp_folder = os.path.join(faraday_user_home, folder)
        checkFolder(fp_folder)

def checkFolder(folder):
    """Checks whether a folder exists and creates it if it doesn't.

    """
    if not os.path.isdir(folder):
        print "Creating %s" % folder
        os.mkdir(folder)

def printBanner():
    """Prints Faraday's ascii banner.

    """
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
    print "[+] Starting Faraday IDE."

    
def main():
    """Main.

    Main function for launcher.

    """

    printBanner()
    if checkDependencies():
        setConf()
        checkConfiguration()
        startFaraday()
    else:
        print "Dependencies not met. Unable to start Faraday."


if __name__ == '__main__':
    main()