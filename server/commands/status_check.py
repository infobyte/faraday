import requests
from colorama import init
from colorama import Fore, Back, Style
import socket
from server.utils.daemonize import is_server_running
import subprocess
import sqlalchemy
from config.configuration import getInstanceConfiguration
from utils import dependencies


CONF = getInstanceConfiguration()

import server.utils.logger

logger = server.utils.logger.get_logger()

init()



def check_server_running():
    pid = is_server_running()
    if pid is not None:
        print('Faraday Server is Running. PID:{PID} {green} Running. {white}\
        '.format(green=Fore.GREEN, PID=pid, white=Fore.WHITE))
        return True
    else:
        print('Faraday Server is not running {red} Not Running. {white} \
        '.format(red=Fore.RED, white=Fore.WHITE))
        return True

def check_open_ports():
    pass

def check_postgres():

    try:
        if db.sessions.query(Workspace).count():
            print("PostgreSQL is running")
    except:
        print('Could not connect to postgresql, please check if database is running')
    

    
def check_client():
    port_rest = CONF.getApiRestfulConInfoPort()

    try:
        response_rest = requests.get('http://localhost:%s/status/check' % port_rest)
        print "Faraday GTK is running"
    except:
        print('WARNING. Faraday GTK is not running')

def check_server_dependencies():

    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file='requirements_server.txt')

    print("Checking server's dependencies")


    if conflict_deps:
        print("Some dependencies are old. Update them with \"pip install -r requirements_server.txt -U\"")
        print("Dependecies to update: ",", ".join(conflict_deps))


    if missing_deps:     
        print("Dependencies not met. Please refer to the documentation in order to install them. ",
                         ", ".join(missing_deps))

def check_gtk_dependencies():
    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file='requirements.txt')

    print("Checking GTK's dependencies")


    if conflict_deps:
        print("Some dependencies are old. Update them with \"pip install -r requirements_server.txt -U\"")
        print("Dependecies to update: ",", ".join(conflict_deps))


    if missing_deps:     
        print("Dependencies not met. Please refer to the documentation in order to install them. ",
                         ", ".join(missing_deps))



def full_status_check():
    print('{red} Incomplete Check {white}.'.format(red=Fore.RED, white=Fore.WHITE))
    check_server_running()
    check_open_ports()
    check_postgres()
    check_client()
    check_server_dependencies()
    check_gtk_dependencies()