"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import os
import socket

import sqlalchemy
from colorama import init
from colorama import Fore

import faraday.server.config
from faraday.server.web import app
from faraday.server.models import db
from faraday.server.config import CONST_FARADAY_HOME_PATH
from faraday.server.utils.daemonize import is_server_running
import faraday_plugins

init()


def check_server_running():
    port = int(faraday.server.config.faraday_server.port)
    pid = is_server_running(port)
    return pid


def check_open_ports():
    address =  faraday.server.config.faraday_server.bind_address
    port = int(faraday.server.config.faraday_server.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((address, port))
    if result == 0:
        return True
    else:
        return False


def check_postgres():
    with app.app_context():
        try:
            result = (db.session.query("version()").one(),db.session.query("current_setting('server_version_num')").one())
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


def check_storage_permission():

    path = os.path.join(CONST_FARADAY_HOME_PATH, 'storage', 'test')

    try:
        os.mkdir(path)
        os.rmdir(path)
        return True
    except OSError:
        return None


def print_config_info():
    print('\n{white}Showing faraday server configuration'.format(white=Fore.WHITE))
    print('{blue} {KEY}: {white}{VALUE}'.
          format(KEY='version', VALUE=faraday.__version__, white=Fore.WHITE, blue=Fore.BLUE))

    data_keys = ['bind_address', 'port', 'websocket_port', 'debug']
    for key in data_keys:
        print('{blue} {KEY}: {white}{VALUE}'.
              format(KEY=key, VALUE=getattr(faraday.server.config.faraday_server, key), white=Fore.WHITE, blue=Fore.BLUE))

    print('\n{white}Showing faraday plugins data'.format(white=Fore.WHITE))
    print('{blue} {KEY}: {white}{VALUE}'.
          format(KEY='version', VALUE=faraday_plugins.__version__, white=Fore.WHITE, blue=Fore.BLUE))

    print('\n{white}Showing dashboard configuration'.format(white=Fore.WHITE))
    data_keys = ['show_vulns_by_price']
    for key in data_keys:
        print('{blue} {KEY}: {white}{VALUE}'.
              format(KEY=key, VALUE=getattr(faraday.server.config.dashboard, key), white=Fore.WHITE, blue=Fore.BLUE))

    print('\n{white}Showing storage configuration'.format(white=Fore.WHITE))
    data_keys = ['path']
    for key in data_keys:
        print('{blue} {KEY}: {white}{VALUE}'.
              format(KEY=key, VALUE=getattr(faraday.server.config.storage, key), white=Fore.WHITE, blue=Fore.BLUE))


def print_postgresql_status():
    """Prints the status of PostgreSQL using check_postgres()"""
    exit_code = 0
    result = check_postgres()


    if result == False:
        print('[{red}-{white}] Could not connect to PostgreSQL, please check if database is running'\
            .format(red=Fore.RED, white=Fore.WHITE))
        exit_code = 1
        return exit_code
    elif result == None:
        print('[{red}-{white}] Database not initialized. Execute: faraday-manage initdb'\
            .format(red=Fore.RED, white=Fore.WHITE))
        exit_code = 1
        return exit_code
    elif int(result[1][0])<90400:
        print('[{red}-{white}] PostgreSQL is running, but needs to be 9.4 or newer, please update PostgreSQL'.\
            format(red=Fore.RED, white=Fore.WHITE))
    elif result:
        print('[{green}+{white}] PostgreSQL is running and up to date'.\
            format(green=Fore.GREEN, white=Fore.WHITE))
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
    """Prints Status of farday using check_server_running() """

    #Prints Status of the server using check_server_running()
    pid = check_server_running()
    if pid is not None:
        print('[{green}+{white}] Faraday Server is running. PID:{PID} \
        '.format(green=Fore.GREEN, PID=pid, white=Fore.WHITE))
    else:
        print('[{red}-{white}] Faraday Server is not running {white} \
        '.format(red=Fore.RED, white=Fore.WHITE))


def print_config_status():
    """Prints Status of the configuration using check_credentials(), check_storage_permission() and check_open_ports()"""

    check_server_running()
    check_postgres()

    if check_storage_permission():
        print('[{green}+{white}] /.faraday/storage -> Permission accepted' \
            .format(green=Fore.GREEN, white=Fore.WHITE))
    else:
        print('[{red}-{white}] /.faraday/storage -> Permission denied'\
            .format(red=Fore.RED, white=Fore.WHITE))

    if check_open_ports():
        print("[{green}+{white}] Port {PORT} in {ad} is open"\
            .format(PORT=faraday.server.config.faraday_server.port, green=Fore.GREEN,white=Fore.WHITE,ad=faraday.server.config.faraday_server.bind_address))
    else:
        print("[{red}-{white}] Port {PORT} in {ad} is not open"\
            .format(PORT=faraday.server.config.faraday_server.port,red=Fore.RED,white=Fore.WHITE,ad =faraday.server.config.faraday_server.bind_address))


def full_status_check():
    print_config_info()

    print('\n{white}Checking if postgreSQL is running...'.format(white=Fore.WHITE))
    print_postgresql_status()
    print_postgresql_other_status()

    print('\n{white}Checking if Faraday is running...'.format(white=Fore.WHITE))
    print_faraday_status()

    print('\n{white}Checking Faraday config...{white}'.format(white=Fore.WHITE))
    print_config_status()
