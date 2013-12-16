#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""
Main module for application
"""

import sys
import os

                                                                      
                                        
if (sys.platform == "darwin"):
    print "[+] Forcing path for %s" % sys.platform
    sys.path.append("/System/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/")

     
              
                    
                                                                                        
                                                
import time
import optparse

from config.configuration import getInstanceConfiguration
                                               
                                                
                                            
from model.application import MainApplication

try:
    from utils.profilehooks import profile
except ImportError:
                                                                       
    def profile(fn, *args, **kwargs):
        return fn

                                                                     
sys.path.insert(0, os.path.dirname(__file__))
                                                                     

                                                                                

def checkDependencies():
    """
    before starting checks that all is needed is installed
    """
                          
    
                                                                                       
    
                          
    if not os.path.exists("/bin/bash"):
                                                  
        print "/bin/bash not present in the system!"
        return False
    return True

                                                                                
def setupOptions(parser):
                                                  
    parser.add_option('-n', '--hostname', action="store", dest="host", default=False, help="Sets the hostname where api XMLRPCServe will listen. Default = localhost")
    parser.add_option('-p', '--port', action="store", dest="port", default=9876, help="Sets the port where api XMLRPCServer will listen. Default = 9876")
    parser.add_option('-d', '--debug', action="store_true", dest="debug", default=False, help="Enables debug mode. Default = disabled")
    parser.add_option('--profile', action="store_true", dest="profile", default=False, help="Enables application profiling. When this option is used --profile-output and --profile-depth can also be used. Default = disabled")
    parser.add_option('--profile-output', action="store", dest="profile_output", default=None, help="Sets the profile output filename. If no value is provided, standard output will be used")
    parser.add_option('--profile-depth', action="store", dest="profile_depth", default=500, help="Sets the profile number of entries (depth). Default = 500")
    parser.add_option('--disable-excepthook', action="store_true", dest="disableexcepthook", default=False, help="Disable the application Exception hook that allows to send error reports to developers.")
    parser.add_option('--disable-login', action="store_true", dest="disablelogin", default=False, help="Disable the auth splash screen.")
                                                                                                                                                     



                                                                                

def main(args):

    parser = optparse.OptionParser()
    setupOptions(parser)
    options, args = parser.parse_args(args[1:])
                                                                     

    if checkDependencies():

        CONF = getInstanceConfiguration()

        CONF.setDebugStatus(False)
        if options.debug:
            CONF.setDebugStatus(True)
        
        if options.host and options.port:
            CONF.setApiConInfo(options.host, int(options.port))
            print "[+] setting api_conn_info = ", CONF.getApiConInfo()
                                                                     
                                   

                                              
                                                   

                                   
                                         
        main_app = MainApplication()

        if options.disablelogin:
            CONF.setAuth(False)

        if not options.disableexcepthook:
            main_app.enableExceptHook()
            
                                                                                                              
                                                                                            
        if options.profile:
            print "%s will be started with a profiler attached. Performance may be affected." % CONF.getAppname()
            start = profile(main_app.start, filename=options.profile_output, entries=int(options.profile_depth))
        else:
            start = main_app.start

        exit_status = start()
                    
        os._exit(exit_status)
    else:
        print "%s cannot start!\nDependecies are not met." % CONF.getAppname()

                                                                                
if __name__ == '__main__':
    main(sys.argv)
