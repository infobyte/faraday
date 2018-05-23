import requests
import subprocess
import sqlalchemy
import socket
import server.utils.logger
from colorama import init
from colorama import Fore, Back, Style
from server.utils.daemonize import is_server_running
from server.models import db
from server.web import app
from config.configuration import getInstanceConfiguration
from utils import dependencies


CONF = getInstanceConfiguration()

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
    with app.app_context():
        try:
            result = str(db.engine.execute("SELECT version()"))
            print("PostgreSQL is running")
        except sqlalchemy.exc.OperationalError:
            print('Could not connect to postgresql, please check if database is running')
    
def check_client():
    port_rest = CONF.getApiRestfulConInfoPort()

    try:
        response_rest = requests.get('http://localhost:%s/status/check' % port_rest)
        print "Faraday GTK is running"
    except requests.exceptions.ConnectionError:
        print('WARNING. Faraday GTK is not running')

def check_server_dependencies():

    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file='requirements_server.txt')

    if conflict_deps:
        print("Some dependencies are old. Update them with \"pip install -r requirements_server.txt -U\"")
        print("Dependecies to update: ",", ".join(conflict_deps))

    if missing_deps:     
        print("Dependencies not met. Please refer to the documentation in order to install them. ",
                         ", ".join(missing_deps))

def check_gtk_dependencies():
    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file='requirements.txt')

    if conflict_deps:
        print("Some dependencies are old. Update them with \"pip install -r requirements_server.txt -U\"")
        print("Dependecies to update: ",", ".join(conflict_deps))

    if missing_deps:     
        print("Dependencies not met. Please refer to the documentation in order to install them. ",
                         ", ".join(missing_deps))

def check_credentials():
    api_username = CONF.getAPIUsername()
    api_password = CONF.getAPIPassword()
    
    values = {'email': api_username , 'password': api_password}
 
    r = requests.post('http://localhost:5985/_api/login', json=values)

    if r.status_code == 200 and 'user' in r.json()['response']:
        print('Credentials matched')
    elif r.status_code == 400:
        print('Error. Credentials does not match')
    elif r.status_code == 500:
        print('Server failed with unexpected error. check if databaseservice is working')
            

def full_status_check():
    print('{red} Incomplete Check {white}.'.format(red=Fore.RED, white=Fore.WHITE))
    check_server_running()
    check_open_ports()
    check_postgres()
    check_client()
    check_server_dependencies()
    check_gtk_dependencies()
    check_credentials()