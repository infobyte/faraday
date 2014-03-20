#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import sys
import os
# XXX: review this!!! it is not correct to hardcode the path this way!!
# python version might not be correct...
if (sys.platform == "darwin"):
    print "[+] Forcing path for %s" % sys.platform
    sys.path.append("/System/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/")
# XXX: optparse has been deprected
# import optparse
import argparse

from config.configuration import getInstanceConfiguration
from model.application import MainApplication

try:
    from utils.profilehooks import profile
except ImportError:
    # if profile module is not installed we use a dummy to avoid errors
    def profile(fn, *args, **kwargs):
        return fn
# XXX: force Python to search modules in the current directory first
sys.path.insert(0, os.path.dirname(__file__))


def checkDependencies():
    """
    before starting checks that all is needed is installed
    """
    # TODO: implement this!
    # if not os.path.exists("/bin/bash"):
    #     print "/bin/bash not present in the system!"
    #     return False
    return True


def setupOptions(parser):
    #TODO: we have to define all options supported
    parser.add_argument('-n', '--hostname', action="store", dest="host", default=False, help="Sets the hostname where api XMLRPCServe will listen. Default = localhost")
    parser.add_argument('-p', '--port', action="store", dest="port", default=9876, help="Sets the port where api XMLRPCServer will listen. Default = 9876")
    parser.add_argument('-d', '--debug', action="store_true", dest="debug", default=False, help="Enables debug mode. Default = disabled")
    parser.add_argument('--profile', action="store_true", dest="profile", default=False, help="Enables application profiling. When this option is used --profile-output and --profile-depth can also be used. Default = disabled")
    parser.add_argument('--profile-output', action="store", dest="profile_output", default=None, help="Sets the profile output filename. If no value is provided, standard output will be used")
    parser.add_argument('--profile-depth', action="store", dest="profile_depth", default=500, help="Sets the profile number of entries (depth). Default = 500")
    parser.add_argument('--disable-excepthook', action="store_true", dest="disableexcepthook", default=False, help="Disable the application Exception hook that allows to send error reports to developers.")
    parser.add_argument('--disable-login', action="store_true", dest="disablelogin", default=False, help="Disable the auth splash screen.")
    parser.add_argument('--gui', action="store", dest="gui", default="qt3", help="Disable the gui and use your own shell")


def main(args):

    parser = argparse.ArgumentParser()
    setupOptions(parser)
    args = parser.parse_args(args[1:])

    # TODO: make all the necessary things to handle each option entered...
    if checkDependencies():

        CONF = getInstanceConfiguration()

        CONF.setDebugStatus(False)
        if args.debug:
            CONF.setDebugStatus(True)

        if args.host and args.port:
            CONF.setApiConInfo(args.host, int(args.port))
            print "[+] setting api_conn_info = ", CONF.getApiConInfo()

        main_app = MainApplication(args)

        if args.disablelogin:
            CONF.setAuth(False)

        if not args.disableexcepthook:
            main_app.enableExceptHook()

        # something interesting to do when profiling is mixing
        # the cProfile output with kcachegrind like this:
        # http://stackoverflow.com/questions/1896032/using-cprofile-results-with-kcachegrind
        if args.profile:
            print "%s will be started with a profiler\
                attached. Performance may be affected." % CONF.getAppname()
            start = profile(main_app.start,
                            filename=args.profile_output,
                            entries=int(args.profile_depth))
        else:
            start = main_app.start

        exit_status = start()

        #os._exit(exit_status)
    else:
        print "%s cannot start!\nDependecies are not met." % CONF.getAppname()


if __name__ == '__main__':
    main(sys.argv)
