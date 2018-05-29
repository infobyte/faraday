import requests
import sqlalchemy
import socket
import os
import server.config
from colorama import init
from colorama import Fore, Back, Style
from server.utils.daemonize import is_server_running
from server.models import db
from server.web import app
from config.configuration import getInstanceConfiguration
from utils import dependencies


CONF = getInstanceConfiguration()


init()


def check_postgres():
	tmp = os.popen("ps -Af").read()
	if "postgresql" in tmp:
		return True
	else:
		return False


def check_active_user():
	with app.app_context():	
		try:
			active_users = db.engine.execute('SELECT active FROM faraday_user')
			for item in active_users:
				if item[0] == True:
					return True
		except sqlalchemy.exc.OperationalError:
			return 0


def check_server_running():
    pid = is_server_running()
    return pid
    

def check_client_running():
    port_rest = CONF.getApiRestfulConInfoPort()

    try:
        response_rest = requests.get('http://{}:{}/status/check'.format(server.config.faraday_server.bind_address,port_rest))
        return True 
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.InvalidURL:
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


def check_open_ports():
   address =  server.config.faraday_server.bind_address
   port = int(server.config.faraday_server.port)
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   result = sock.connect_ex((address,port))
   if result == 0:
       return True
   else:
       return False


def full_status_check():
     

    #Checking PostgreSQL
    print('\n{white}Checking if PostgreSQL is running...'.format(white=Fore.WHITE))   
    result = check_postgres()
    if result:
        print('[{green}+{white}] PostgreSQL is running'.\
            format(green=Fore.GREEN, white=Fore.WHITE))
    
    else:
        print('[{red}-{white}] Could not connect to PostgreSQL, please check if database is running'\
            .format(red=Fore.RED, white=Fore.WHITE))
        return

    if check_active_user():
    	print("[{green}+{white}] Active user exists".format(green=Fore.GREEN, white=Fore.WHITE))
    elif check_active_user() == 0:
    	print("[{red}-{white}] Faraday database non existant".format(red=Fore.RED, white=Fore.WHITE))
    else:
    	print("[{red}-{white}] Active user doesn't exists".format(red=Fore.RED, white=Fore.WHITE))


    #Checking status
    print('\n{white}Checking if Faraday is running...'.format(white=Fore.WHITE))
    pid = check_server_running()
    if pid is not None:
        print('[{green}+{white}] Faraday Server is Running. PID:{PID} \
        '.format(green=Fore.GREEN, PID=pid, white=Fore.WHITE))
    else:
        print('[{red}-{white}] Faraday Server is not running {white} \
        '.format(red=Fore.RED, white=Fore.WHITE))

    if check_client_running():
        print('[{green}+{white}] Faraday GTK is running'.\
            format(green=Fore.GREEN, white=Fore.WHITE))
    else:
        print('[{yellow}-{white}] Faraday GTK is not running'\
            .format(yellow=Fore.YELLOW, white=Fore.WHITE))


    #Checking dependencies
    print('\n{white}Checking Faraday dependencies...'.format(white=Fore.WHITE))   
    status, server_dep = check_server_dependencies()
    
    if status == True:
        print('[{red}-{white}] Some server\'s dependencies are old. Update them with \"pip install -r requirements_server.txt -U\": (' + ','.join(server_dep) + ')') \
            .format(red=Fore.RED, white=Fore.WHITE)

    elif status == 0:
        print('[{red}-{white}] Server\'s dependencies not met. Install them with \"pip install -r requirements_server.txt -U\": (' + ','.join(server_dep) + ')')\
            .format(red=Fore.RED, white=Fore.WHITE)
        
    else:
        print('[{green}+{white}] Server\'s dependencies met' \
            .format(green=Fore.GREEN, white=Fore.WHITE))

    status, client_dep = check_client_dependencies()
    if status == True:
        print('[{red}-{white}] Some client\'s dependencies are old. Update them with \"pip install -r requirements.txt -U\": (' + ','.join(client_dep) + ')') \
            .format(red=Fore.RED, white=Fore.WHITE)
        
    elif status == 0:
        print('[{red}-{white}] Client\'s dependencies not met. Install them with \"pip install -r requirements.txt -U\": (' + ','.join(client_dep) + ')')\
            .format(red=Fore.RED, white=Fore.WHITE)
            
    else:
        print('[{green}+{white}] Client\'s dependencies met'\
            .format(green=Fore.GREEN, white=Fore.WHITE))

       
    #Checking config
    print('\n{white}Checking Faraday config...{white}'.format(white=Fore.WHITE))
    if pid and result:    
        status_code = check_credentials()
        if status_code == 200:
            print('[{green}+{white}] User\'s credentials matched'.format(green=Fore.GREEN, white=Fore.WHITE))
        elif status_code == 400:
            print('[{red}-{white}] Error. User\'s credentials do not match' \
                .format(red=Fore.RED, white=Fore.WHITE))
    else:
        print('[{red}-{white}] Failed checking user\'s credentials. Either Faraday Server is not running or database is not working'\
        	.format(red=Fore.RED, white=Fore.WHITE))

    if check_storage_permission():
        print('[{green}+{white}] ~/.faraday/storage -> Permission accepted' \
            .format(green=Fore.GREEN, white=Fore.WHITE))
    else:
        print('[{red}-{white}] ~/.faraday/storage -> Permission denied'\
            .format(red=Fore.RED, white=Fore.WHITE))

    if check_open_ports():
        print "[{green}+{white}] Port {PORT} in {ad} is open"\
            .format(PORT=server.config.faraday_server.port, green=Fore.GREEN,white=Fore.WHITE,ad=server.config.faraday_server.bind_address)
    else:
        print "[{red}-{white}] Port {PORT} in {ad} is not open"\
            .format(PORT=server.config.faraday_server.port,red=Fore.RED,white=Fore.WHITE,ad =server.config.faraday_server.bind_address)
