#!/usr/bin/env python2
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

# TODO:
# - Make a launcher class and remove globals for attributes!
# - Handle requirements dinamically.
# - Additionally parse arguments from file.
# - Colorize!
# - Refactor the still remaining bash launcher

import os
import sys
import shutil
import argparse
import colorama

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__))) # Necessary?
from config.configuration import getInstanceConfiguration
from model.application import MainApplication
from utils.profilehooks import profile # statically added


REQUIREMENTS_FILE = 'requirements.txt'
FARADAY_HOME_PATH = '~/.faraday'
FARADAY_FOLDER_LIST = [ "config", "data", "images", 
                        "persistence", "plugins",
                        "report", "temp", "zsh" ]

def getParserArgs():
    """Parser setup for faraday launcher arguments.

    """

    parser = argparse.ArgumentParser(
        description="Faraday's launcher parser.", 
        fromfile_prefix_chars='@')

    parser_connection = parser.add_argument_group('connection')
    parser_profile = parser.add_argument_group('profiling')
    #parser_gui = parser.add_argument_group('gui')
    parser_gui_ex = parser.add_mutually_exclusive_group()

    parser_connection.add_argument('-n', '--hostname', action="store", dest="host", 
        default="localhost", 
        help="The hostname where api XMLRPCServer will listen. Default = localhost")

    parser_connection.add_argument('-p', '--port', action="store", dest="port", 
        default=9876, type=int,
        help="Sets the port where api XMLRPCServer will listen. Default = 9876")

    parser.add_argument('-d', '--debug', action="store_true", dest="debug", 
        default=False, 
        help="Enables debug mode. Default = disabled")

    parser_profile.add_argument('--profile', action="store_true", dest="profile", 
        default=False, 
        help="Enables application profiling. When this option is used \
         --profile-output and --profile-depth can also be used. Default = disabled")

    parser_profile.add_argument('--profile-output', action="store",
        dest="profile_output",
        default=None, 
        help="Sets the profile output filename. If no value is provided, standard \
        output will be used")

    parser_profile.add_argument('--profile-depth', action="store", 
        dest="profile_depth", type=int,
        default=500, 
        help="Sets the profile number of entries (depth). Default = 500")

    parser.add_argument('--disable-excepthook', action="store_true", 
        dest="disable_excepthook", 
        default=False, 
        help="Disable the application exception hook that allows to send error \
        reports to developers.")

    parser.add_argument('--disable-login', action="store_true", dest="disable_login", 
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
    """Dependency resolver based on a previously specified REQUIREMENTS_FILE.

    Currently checks a list of dependencies from a file and asks for user
    confirmation on whether to install it with a specific version or not.

    """

    modules = []
    f = open(REQUIREMENTS_FILE)
    for line in f:
        if line.find('#'):
            modules.append([line[:line.index('=')], line[line.index('=')+2:]])
    f.close()

    for module in modules:
        try:
            __import__(module[0])
        except ImportError:          
            if query_user_bool("Missing module %s." \
                " Do you wish to install it?" % module[0]):
                # TODO: Cambiarlo por un subprocess.
                print "pip2 install %s==%s" % (module[0], module[1])
            else:
                return False
    return True

def startProfiler(app, output, depth):
    """Profiler handler.

    Will start a profiler on the given application in a specified output with
    a custom depth.

    TODO: Check if it's necessary to add a dummy in case o failed import.

    """
    print "Faraday will be started with a profiler attached." \
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

def env():
    # TODO: Make a launcher class and remove globals for attributes.
    # Debugging purposes ONLY. Will be replaced soon.

    global faraday_user_home
    global faraday_base
    global faraday_plugins_path 
    global faraday_plugins_basepath
    
    faraday_user_home = os.path.expanduser(FARADAY_HOME_PATH)
    faraday_base = os.path.dirname(os.path.realpath(__file__))
    faraday_plugins_path = "%s/plugins" % faraday_user_home
    faraday_plugins_basepath = "%s/plugins/repo/" % faraday_base


def checkPlugins(dev_mode=False):
    """Checks and handles Farada's plugin status.

    When dev_mode is True, the user enters in development mode and the plugins will
    be replaced with the latest ones. 

    Otherwise, it checks if the plugin folders exists or not, and creates it
    with its content.

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

def checkConfiguration():
    checkPlugins(args.dev_mode)
    #checkQtrc()
    #restoreQtrc()
    #checkZSH()
    checkFolderList(FARADAY_FOLDER_LIST)
    #checkHelpers()

def checkFolderList(folderlist):
    for folder in folderlist:
        fp_folder = "%s/%s" % (faraday_user_home, folder)
        checkFolder(fp_folder)

def checkFolder(folder):
    if not os.path.isdir(folder):
        print "Creating %s" % folder
        os.mkdir(folder)

def main():
    """Main.

    Main function for launcher.

    TODO: Use this a a launcher _init_ method?
    """

    env()
    if checkDependencies():
        setConf()
        checkConfiguration()
        startFaraday()
    else:
        print "Dependencies not met. Unable to start Faraday."


if __name__ == '__main__':
    main()