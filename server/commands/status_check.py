from colorama import init
from colorama import Fore, Back, Style

init()


def check_server_running():
    pass


def check_open_ports():
    pass


def full_status_check():
    print('{red} Incomplete Check {white}.'.format(red=Fore.RED, white=Fore.WHITE))
    check_server_running()
    check_open_ports()
