'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import socket

import requests
import sqlalchemy
from colorama import init
from colorama import Fore, Back, Style
from requests.exceptions import InvalidURL, ConnectionError

import faraday.server.config
from faraday.config import constant as CONSTANTS
from faraday.config.configuration import getInstanceConfiguration
from faraday.server.web import app
from faraday.server.models import db
from faraday.server.config import FARADAY_BASE
from faraday.server.utils.daemonize import is_server_running
from faraday.utils import dependencies


CONF = getInstanceConfiguration()

init()


def check_server_running():
    port = int(faraday.server.config.faraday_server.port)
    pid = is_server_running(port)
    return pid


def check_open_ports():
   address =  faraday.server.config.faraday_server.bind_address
   port = int(faraday.server.config.faraday_server.port)
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   result = sock.connect_ex((address,port))
   if result == 0:
       return True
   else:
       return False


def check_postgres():
    with app.app_context():
        try:
            result = (str(db.session.query("version()").one()),db.session.query("current_setting('server_version_num')").one())
            return result
        except sqlalchemy.exc.OperationalError:
            return False
        except sqlalchemy.exc.ArgumentError:
            return None


def check_locks_postgresql():
    with app.app_context():
        psql_status = check_postgres()
        if psql_status:
            result = db.engine.execute("""SELECT blocked_locks.pid     AS blocked_pid, 
                                            blocked_activity.usename  AS blocked_user, 
                                            blocking_locks.pid     AS blocking_pid, 
                                            blocking_activity.usename AS blocking_user, 
                                            blocked_activity.query    AS blocked_statement, 
                                            blocking_activity.query   AS current_statement_in_blocking_process 
                                        FROM  pg_catalog.pg_locks         blocked_locks 
                                            JOIN pg_catalog.pg_stat_activity blocked_activity  ON blocked_activity.pid = blocked_locks.pid 
                                        JOIN pg_catalog.pg_locks         blocking_locks 
                                            ON blocking_locks.locktype = blocked_locks.locktype 
                                            AND blocking_locks.DATABASE IS NOT DISTINCT FROM blocked_locks.DATABASE 
                                            AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation 
                                            AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page 
                                            AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple 
                                            AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid 
                                            AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid 
                                            AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid 
                                            AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid 
                                            AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid 
                                            AND blocking_locks.pid != blocked_locks.pid 
                                        JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid 
                                            WHERE NOT blocked_locks.GRANTED;""")
            fetch = result.fetchall()
            if fetch:
                return True 
            else:
                return False
        
        else:
            return None


def check_postgresql_encoding():
    with app.app_context():
        psql_status = check_postgres()
        if psql_status:
            encoding = db.engine.execute("SHOW SERVER_ENCODING").first()[0]
            return encoding
        else:
            return None


def check_client():

    port_rest = CONF.getApiRestfulConInfoPort()

    if port_rest is None:
        port_rest = "9977"
    try:
        response_rest = requests.get('http://{}:{}/status/check'.format(faraday.server.config.faraday_server.bind_address,port_rest))
        return True 
    except ConnectionError:
        return False
    except InvalidURL:
    	return False


def check_server_dependencies():

    requirements_file=os.path.join(FARADAY_BASE,'requirements_server.txt')
    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file=requirements_file)

    if conflict_deps:
        return True, conflict_deps
        
    if missing_deps:
        return 0, missing_deps     

    if not conflict_deps and not missing_deps:  
        return None, None


def check_client_dependencies():

    requirements_file=os.path.join(FARADAY_BASE,'requirements.txt')
    installed_deps, missing_deps, conflict_deps = dependencies.check_dependencies(
        requirements_file=requirements_file)

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
    
    address =  faraday.server.config.faraday_server.bind_address
    port = int(faraday.server.config.faraday_server.port)
    
    values = {'email': api_username , 'password': api_password}
 
    try:
        r = requests.post('http://{ADDRESS}:{PORT}/_api/login'.format(ADDRESS=address,PORT=port), json=values)

        if r.status_code == 200 and 'user' in r.json()['response']:
            return 200            
        elif r.status_code == 400:
            return 400
        elif r.status_code == 500:
            return 500

    except ConnectionError:
        return None


def check_storage_permission():
    
    path = os.path.join(CONSTANTS.CONST_FARADAY_HOME_PATH,'storage/test')
    
    try:
        os.mkdir(path)
        os.rmdir(path)
        return True        
    except OSError:
        return None


def print_postgresql_status():
    """Prints the status of PostgreSQL using check_postgres()"""
    exit_code = 0
    result = check_postgres()
    print(result[0])
    if result[1]<90400:
        print('[{red}-{white}] PostgreSQL is running, but needs to be 9.4 or newer, please update PostgreSQL'.\
            format(red=Fore.RED, white=Fore.WHITE))
    elif result:
        print('[{green}+{white}] PostgreSQL is running and up to date'.\
            format(green=Fore.GREEN, white=Fore.WHITE))
        return exit_code
    elif result == False:
        print('[{red}-{white}] Could not connect to PostgreSQL, please check if database is running'\
            .format(red=Fore.RED, white=Fore.WHITE))
        exit_code = 1
        return exit_code
    elif result == None:
        print('[{red}-{white}] Database not initialized. Execute: faraday-manage initdb'\
            .format(red=Fore.RED, white=Fore.WHITE))
        exit_code = 1
        return exit_code


def print_postgresql_other_status():
    """Prints the status of locks in Postgresql using check_locks_postgresql() and
    prints Postgresql encoding using check_postgresql_encoding()"""

    lock_status = check_locks_postgresql()
    if lock_status:
        print('[{yellow}-{white}] Warning: PostgreSQL lock detected.' \
            .format(yellow=Fore.YELLOW, white=Fore.WHITE))
    elif lock_status == False:
        print('[{green}+{white}] PostgreSQL lock not detected. '.\
            format(green=Fore.GREEN, white=Fore.WHITE))
    elif lock_status == None:
        pass

    encoding = check_postgresql_encoding()
    if encoding:
        print('[{green}+{white}] PostgreSQL encoding: {db_encoding}'.\
                format(green=Fore.GREEN, white=Fore.WHITE, db_encoding=encoding))
    elif encoding == None:
        pass


def print_faraday_status():
    """Prints Status of farday using check_server_running() and check_client"""

    #Prints Status of the server using check_server_running()
    pid = check_server_running()
    if pid is not None:
        print('[{green}+{white}] Faraday Server is running. PID:{PID} \
        '.format(green=Fore.GREEN, PID=pid, white=Fore.WHITE))
    else:
        print('[{red}-{white}] Faraday Server is not running {white} \
        '.format(red=Fore.RED, white=Fore.WHITE))

    #Prints Status of the client using check_client()
    if check_client():
        print('[{green}+{white}] Faraday GTK is running'.\
            format(green=Fore.GREEN, white=Fore.WHITE))
    else:
        print('[{yellow}-{white}] Faraday GTK is not running'\
            .format(yellow=Fore.YELLOW, white=Fore.WHITE))


def print_depencencies_status():
    """Prints Status of the dependencies using check_server_dependencies() and check_client_dependencies()"""
    
    status, server_dep = check_server_dependencies()
    if status == True:
        print('[{red}-{white}] Some server dependencies are old: [' + ', '.join(server_dep) + ']. Update them with \"pip install -r requirements_server.txt -U\"') \
            .format(red=Fore.RED, white=Fore.WHITE)

    elif status == 0:
        print('[{red}-{white}] Client dependencies not met: [' + ', '.join(server_dep) + '] Install them with \"pip install -r requirements_server.txt -U\"')\
            .format(red=Fore.RED, white=Fore.WHITE)
        
    else:
        print('[{green}+{white}] Server dependencies met' \
            .format(green=Fore.GREEN, white=Fore.WHITE))

    status, client_dep = check_client_dependencies()
    if status == True:
        print('[{red}-{white}] Some client dependencies are old: [' + ', '.join(client_dep) + ']. Update them with \"pip install -r requirements.txt -U\"') \
            .format(red=Fore.RED, white=Fore.WHITE)
        
    elif status == 0:
        print('[{red}-{white}] Client dependencies not met: [' + ', '.join(client_dep) + ']. Install them with \"pip install -r requirements.txt -U\"')\
            .format(red=Fore.RED, white=Fore.WHITE)
            
    else:
        print('[{green}+{white}] Client dependencies met'\
            .format(green=Fore.GREEN, white=Fore.WHITE))


def print_config_status():
    """Prints Status of the configuration using check_credentials(), check_storage_permission() and check_open_ports()"""

    pid = check_server_running()
    result = check_postgres()
    if pid and result:    
        status_code = check_credentials()
        if status_code == 200:
            print('[{green}+{white}] Credentials matched'.format(green=Fore.GREEN, white=Fore.WHITE))
        elif status_code == 400:
            print('[{red}-{white}] Error. Credentials does not match' \
                .format(red=Fore.RED, white=Fore.WHITE))
    else:
        print('[{red}-{white}] Credentials can not be checked. Either Faraday Server not running or database not working'.format(red=Fore.RED, white=Fore.WHITE))

    if check_storage_permission():
        print('[{green}+{white}] /.faraday/storage -> Permission accepted' \
            .format(green=Fore.GREEN, white=Fore.WHITE))
    else:
        print('[{red}-{white}] /.faraday/storage -> Permission denied'\
            .format(red=Fore.RED, white=Fore.WHITE))

    if check_open_ports():
        print "[{green}+{white}] Port {PORT} in {ad} is open"\
            .format(PORT=faraday.server.config.faraday_server.port, green=Fore.GREEN,white=Fore.WHITE,ad=faraday.server.config.faraday_server.bind_address)
    else:
        print "[{red}-{white}] Port {PORT} in {ad} is not open"\
            .format(PORT=faraday.server.config.faraday_server.port,red=Fore.RED,white=Fore.WHITE,ad =faraday.server.config.faraday_server.bind_address)


def full_status_check():
    print('\n{white}Checking if postgreSQL is running...'.format(white=Fore.WHITE))  
    print_postgresql_status()
    print_postgresql_other_status()

    print('\n{white}Checking if Faraday is running...'.format(white=Fore.WHITE))
    print_faraday_status()

    print('\n{white}Checking Faraday dependencies...'.format(white=Fore.WHITE))   
    print_depencencies_status()

    print('\n{white}Checking Faraday config...{white}'.format(white=Fore.WHITE))
    print_config_status()
