from colorama import init
from colorama import Fore, Back, Style
import socket
from server.utils.daemonize import is_server_running
init()



def check_server_running():
    pid = is_server_running()
    if pid is not None:
        print('Faraday Server is Running. PID:{PID} {green} Running. \
        '.format(green=Fore.GREEN, PID=pid))
        return True
    else:
        print('Faraday Server is not running {red} Not Running. \
        '.format(red=Fore.RED))
        return True

def check_open_ports():
    pass

def full_status_check():
    check_server_running()
    
