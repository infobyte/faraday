#!/usr/bin/env python2
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

# TODO:
# - Pasar en limpio del papel!
# - Manejar dinamicamente los requerimientos?
# - Parsear adicionalmente los argumentos desde un archivo?
# - Agregar outputs y colores a los mismos.
# - Agregar todos los manejos del viejo bash launcher.

import os
import sys
import argparse
import colorama

from config.configuration import getInstanceConfiguration
from model.application import MainApplication
from utils.profilehooks import profile # statically added


REQUIREMENTS_FILE = 'requirements.txt'

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
                " Do you wish to install it?" % module[0]) == "yes":
                # TODO: Cambiarlo por un subprocess.
                print "pip2 install %s==%s" % (module[0], module[1])
            else:
                return False
    return True

def setConf():
    """User configuration management and instantiation.

    Setting framework configuration based either on previously user saved
    settings or default ones.

    """
    args = getParserArgs()
    CONF = getInstanceConfiguration()
    CONF.setDebugStatus(args.debug)
    CONF.setApiConInfo(args.host, args.port)
    CONF.setAuth(args.disable_login)

    main_app = MainApplication(args)

    if not args.disable_excepthook:
            main_app.enableExceptHook()

    if args.profile:
        print "%s will be started with a profiler\
            attached. Performance may be affected." % CONF.getAppname()
        start = profile(main_app.start,
                        filename=args.profile_output,
                        entries=args.profile_depth)
    else:
        start = main_app.start

    exit_status = start()

def main(args):
    """
        Main.
    """

    if checkDependencies():
        setConf()
    else:
        print "Dependencies not met. Unable to start Faraday."


if __name__ == '__main__':
    main(sys.argv)