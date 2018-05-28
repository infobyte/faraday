import requests
import sqlalchemy
import socket
import os
from colorama import init
from colorama import Fore, Back, Style
from server.utils.daemonize import is_server_running
from server.models import db
from server.web import app
from config.configuration import getInstanceConfiguration
from utils import dependencies


CONF = getInstanceConfiguration()


init()


def check_server_running():

    pid = is_server_running()
    return pid
    
def check_open_ports():
    pass

def check_postgres():
    with app.app_context():
        try:
            result = str(db.engine.execute("SELECT version()"))
            return result 
        except sqlalchemy.exc.OperationalError:
            return None
            

def check_client():

    port_rest = CONF.getApiRestfulConInfoPort()

    try:
        response_rest = requests.get('http://localhost:%s/status/check' % port_rest)
        return True 
    except requests.exceptions.ConnectionError:
        return False



def check_server_dependencies():

    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file='requirements_server.txt')

    if conflict_deps:
        return True, conflict_deps
        
    if missing_deps:
        return 0, missing_deps     

    if not conflict_deps and not missing_deps:  
        return None, None


def check_client_dependencies():

    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file='requirements.txt')

    if 'argparse' in conflict_deps:
            conflict_deps.remove('argparse')
    
    if conflict_deps:
        return True, conflict_deps
        
    if missing_deps:
        return 0, missing_deps     

    if not conflict_deps and not missing_deps:  
        return None, None




def check_credentials():

    api_username = CONF.getAPIUsername()
    api_password = CONF.getAPIPassword()
    
    values = {'email': api_username , 'password': api_password}
 
    try:
        r = requests.post('http://localhost:5985/_api/login', json=values)

        if r.status_code == 200 and 'user' in r.json()['response']:
            return 200
            
        elif r.status_code == 400:
            return 400

        elif r.status_code == 500:
            return 500
    except requests.exceptions.ConnectionError:
        return None


def check_storage_permission():

    home = os.path.expanduser("~")
    path = home+'/.faraday/storage/test'

    try:
        os.mkdir(path)
        os.rmdir(path)
        return True        
    except OSError:
        return None


def full_status_check():
     

    #Prints the status of PostreSQL using check_postgres()
    print('\n{white}Checking if postgreSQL is running...'.format(white=Fore.WHITE))   
    result = check_postgres()
    if result:
        print('[{green}+{white}] PostgreSQL is running'.\
            format(green=Fore.GREEN, white=Fore.WHITE))
    
    else:
        print('[{red}-{white}] Could not connect to postgresql, please check if database is running'\
            .format(red=Fore.RED, white=Fore.WHITE))
        return

    print('\n{white}Checking if Faraday is running...'.format(white=Fore.WHITE))
    if check_client():
        print('[{green}+{white}] Faraday GTK is running'.\
            format(green=Fore.GREEN, white=Fore.WHITE))
    else:
        print('[{yellow}-{white}] Faraday GTK is not running'\
            .format(yellow=Fore.YELLOW, white=Fore.WHITE))

    #Prints Status of the server using check_server_running()
    pid = check_server_running()
    if pid is not None:
        print('[{green}+{white}] Faraday Server is Running. PID:{PID} \
        '.format(green=Fore.GREEN, PID=pid, white=Fore.WHITE))
    else:
        print('[{red}-{white}] Faraday Server is not running {white} \
        '.format(red=Fore.RED, white=Fore.WHITE))
    

    check_open_ports()




    print('\n{white}Checking Faraday dependencies...'.format(white=Fore.WHITE))   
    
    status, server_dep = check_server_dependencies()
    
    if status == True:
        print('[{red}-{white}] Some server dependencies are old. Update them with \"pip install -r requirements_server.txt -U\"' \
            .format(red=Fore.RED, white=Fore.WHITE))
        print(('[{blue}*{white}] Failed dependencies: ' + ','.join(server_dep))\
            .format(blue=Fore.BLUE, white=Fore.WHITE))
    elif status == 0:
        print('[{red}-{white}] Server dependencies not met. Install them with \"pip install -r requirements_server.txt -U\"'\
            .format(red=Fore.RED, white=Fore.WHITE))
        print(('[{blue}*{white}] Failed dependencies: ' + ','.join(server_dep))\
            .format(blue=Fore.BLUE, white=Fore.WHITE))
    else:
        print('[{green}+{white}] Server dependencies met' \
            .format(green=Fore.GREEN, white=Fore.WHITE))

    status, client_dep = check_client_dependencies()
    if status == True:
        print('[{red}-{white}] Some client dependencies are old. Update them with \"pip install -r requirements.txt -U\"' \
            .format(red=Fore.RED, white=Fore.WHITE))
        print(('[{blue}*{white}] Failed dependencies: ' + ','.join(client_dep))\
            .format(blue=Fore.BLUE, white=Fore.WHITE))
    elif status == 0:
        print('[{red}-{white}] Client dependencies not met. Install them with \"pip install -r requirements.txt -U\" (' + ','.join(client_dep) + ')')\
            .format(red=Fore.RED, white=Fore.WHITE)
            
    else:
        print('[{green}+{white}] Client dependencies met'\
            .format(green=Fore.GREEN, white=Fore.WHITE))
        

    print('\n{white}Checking Faraday config...{white}'.format(white=Fore.WHITE))
    if pid and result:    
        status_code = check_credentials()
        if status_code == 200:
            print('[{green}+{white}] Credentials matched'.format(green=Fore.GREEN, white=Fore.WHITE))
        elif status_code == 400:
            print('[{red}-{white}] Error. Credentials does not match' \
                .format(red=RED, white=WHITE))
    else:
        print('[{red}-{white}] Either Faraday Server not running or database not working'.format(red=Fore.RED, white=Fore.WHITE))
    
#        elif status_code == 500:
#            print('[{red}FAIL{white}]    Server failed with unexpected error. check if databaseservice is working.' \
#                .format(red=Fore.RED, white=Fore.WHITE))

    if check_storage_permission():
        print('[{green}+{white}] ~/.faraday/storage -> Permission accepted' \
            .format(green=Fore.GREEN, white=Fore.WHITE))
    else:
        print('[{red}-{white}] ~/.faraday/storage -> Permission denied'\
            .format(red=Fore.RED, white=Fore.WHITE))
