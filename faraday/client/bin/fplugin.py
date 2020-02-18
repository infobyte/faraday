"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from builtins import input

import os
import sys
import imp
import shlex
import atexit
import signal
import inspect
import argparse
import readline
from queue import Queue

from faraday.client.plugins import fplugin_utils

from colorama import Fore
from faraday.config.configuration import getInstanceConfiguration
from faraday.client.managers.mapper_manager import MapperManager
from faraday.client.model.controller import ModelController
from faraday.client.persistence.server.server import login_user

CONF = getInstanceConfiguration()

plugins = None


class RawDescriptionAndDefaultsHelpFormatter(argparse.RawDescriptionHelpFormatter,
                                             argparse.ArgumentDefaultsHelpFormatter):
    pass


# Call signature corresponding to a function defined as:
# def main(workspace='', args=[], parser = None):
CURRENT_MAIN_ARGSPEC = inspect.ArgSpec(args=['workspace', 'args', 'parser'], varargs=None, keywords=None,
                                       defaults=('', None, None))

FPLUGIN_INTERACTIVE_LAST_TOKEN = '$last'


def signal_handler(signal, frame):
    print('Bye Bye!')
    os._exit(0)


def dispatch(args, unknown, user_help, username, password):
    session_cookie = login_user(args.url, username, password)
    if not session_cookie:
        raise UserWarning('Invalid credentials!')

    CONF.setDBUser(username)
    CONF.setDBSessionCookies(session_cookie)

    if '--' in unknown:
        unknown.remove('--')

    # We need the ModelController to register all available models
    mappers_manager = MapperManager()
    pending_actions = Queue()
    model_controller = ModelController(mappers_manager, pending_actions)

    if not args.command:
        print(user_help)
        if not args.interactive:
            sys.exit(1)

    if args.command not in list(plugins.keys()):
        sys.stderr.write(Fore.RED +
                         ("ERROR: Plugin %s not found.\n" % args.command) +
                         Fore.RESET)
        if args.interactive:
            return None
        else:
            sys.exit(1)

    from faraday import client # pylint:disable=import-outside-toplevel
    faraday_directory = os.path.dirname(os.path.realpath(os.path.join(client.__file__)))

    plugin_path = os.path.join(faraday_directory, "bin/", args.command + '.py')
    # Get filename and import this
    module_fplugin = imp.load_source('module_fplugin', plugin_path)
    module_fplugin.models.server.FARADAY_UP = False
    module_fplugin.models.server.SERVER_URL = args.url
    module_fplugin.models.server.AUTH_USER = username
    module_fplugin.models.server.AUTH_PASS = password

    call_main = getattr(module_fplugin, 'main', None)

    if call_main is None:
        sys.stderr.write(Fore.RED + "ERROR: Main function not found.\n" + Fore.RESET)
        if args.interactive:
            return None
        else:
            sys.exit(1)

    # Inspect the main function imported from the plugin and decide the best calling option
    main_argspec = inspect.getargspec(call_main)

    if main_argspec != CURRENT_MAIN_ARGSPEC:
        # Function argspec does not match current API.
        # Warn the user and call with original parameteres.
        sys.stderr.write(Fore.YELLOW +
                         "WARNING: Plugin does not follow current call signature. Please update it! [%s.py]\n" % args.command +
                         Fore.RESET)

    obj_id = None

    if {'args', 'parser'} <= set(main_argspec.args):
        # Function accepts args and parser arguments

        new_parser = argparse.ArgumentParser(description=plugins[args.command]['description'],
                                             prog="fplugin %s" % args.command,
                                             formatter_class=RawDescriptionAndDefaultsHelpFormatter)

        ret, obj_id = call_main(workspace=args.workspace, args=unknown, parser=new_parser)

        if obj_id is not None:
            print(obj_id)
    else:
        # Use old API to call plugin
        sys.stderr.write(Fore.YELLOW +
                         "WARNING: Call with arguments and parser not supported.\n" +
                         Fore.RESET)
        ret = call_main(workspace=args.workspace)

    if ret is None:
        ret = 0

    if args.interactive:
        # print ('code = %d' % ret)
        return obj_id
    else:
        sys.exit(ret)


def main():
    global plugins

    signal.signal(signal.SIGINT, signal_handler)

    description = ('Using our plugin you can do different actions in the command line\n'
                   'and interact with Faraday. Faraday comes with some presets for bulk\n'
                   'actions such as object removal, get object information, etc.\n'
                   'Any parameter not recognized by fplugin, or everything after -- will be passed on \n'
                   'to the called script.\n')

    epilog = 'Available scripts:\n'

    plugins = fplugin_utils.get_available_plugins()

    for plugin in sorted(plugins.keys()):
        epilog += '\t- %s: %s\n' % (plugin, plugins[plugin]['description'])

    parser = argparse.ArgumentParser(description=description,
                                     epilog=epilog,
                                     formatter_class=RawDescriptionAndDefaultsHelpFormatter)

    group = parser.add_mutually_exclusive_group()

    group.add_argument('command', nargs='?', help='Command to execute. Example: ./fplugin getAllIps')
    group.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')

    parser.add_argument(
        '-w',
        '--workspace',
        help='Workspace to use',
        default=CONF.getLastWorkspace())

    parser.add_argument(
        '-u',
        '--url',
        help='Faraday Server URL. Example: http://localhost:5985',
        default=CONF.getServerURI())

    parser.add_argument(
        '--username',
        default=CONF.getAPIUsername())

    parser.add_argument(
        '--password',
        default=CONF.getAPIPassword())

    # Only parse known args. Unknown ones will be passed on the the called script
    args, unknown = parser.parse_known_args()

    # print("""\nTo login please provide your valid DB Credentials.\n""")
    # username = raw_input('Username: ')
    # password = getpass.getpass('Password: ')

    if not args.interactive:
        dispatch(args, unknown, parser.format_help(), args.username, args.password)
    else:

        # print ("Loading command history...")
        histfile = os.path.join(CONF.getDataPath(), ".faraday_hist")
        readline.parse_and_bind('tab: complete')
        atexit.register(readline.write_history_file, histfile)

        try:
            readline.read_history_file(histfile)
            # default history len is -1 (infinite), which may grow unruly
            readline.set_history_length(1000)
        except IOError:
            pass

        print("Welcome to interactive Faraday!")
        print("Press CTRL-D or run 'exit' to quit interactive mode.")
        last_id = None

        while True:
            try:
                line = input("> ")

                if line.strip() == 'exit':
                    os._exit(0)

                # Split line read from stdin into argv
                new_args = shlex.split(line)
                new_args += ['--username', args.username, '--password', args.password]

                if '-i' in new_args or '--interactive' in new_args:
                    print('Already in interactive mode!')
                    continue

                if 'h' in new_args or 'help' in new_args:
                    parser.print_help()
                    continue

                if FPLUGIN_INTERACTIVE_LAST_TOKEN in new_args:
                    i = new_args.index(FPLUGIN_INTERACTIVE_LAST_TOKEN)
                    new_args[i] = last_id or ''

                parsed_args, new_unknown = parser.parse_known_args(new_args)
                parsed_args.interactive = True

                last_id = dispatch(parsed_args, new_unknown, parser.format_help(), args.username, args.password) or last_id
                # print '$last = %s' % last_id
            except (EOFError, KeyboardInterrupt):
                print('Bye Bye!')
                sys.exit(0)
            except SystemExit:
                pass


if __name__ == '__main__':
    main()


# I'm Py3
