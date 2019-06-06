import os
import sys
import shutil
import tempfile
from tqdm import tqdm
from colorama import init
from colorama import Fore, Style

try:
    from pip._internal.operations import freeze
except ImportError:  # pip < 10.0
    from pip.operations import freeze

import faraday.config.constant as constants
from faraday.server.commands import status_check

init()

def init_config():
    #Creates the directory where all the info will go to
    path = tempfile.mkdtemp()
    return path

def get_status_check(path):
    #Executes status check from with-in the code and uses stdout to save info to file
    #stdout was the only way to get this information without doing a big refactor
    original_stdout = sys.stdout

    sys.stdout = open(path + '/status_check.txt','wt')
    status_check.full_status_check()
    
    sys.stdout.close()
    sys.stdout = original_stdout


def get_pip_freeze(path):
    #Executes pip freeze internally and saves the info a pip_freeze.txt file
    pip_freeze = freeze.freeze()
    pip_file = open(path + '/pip_freeze.txt', 'a')
    for line in pip_freeze:
        pip_file.write(line)
        pip_file.write('\n')
    pip_file.close()

def get_logs(path):
    #Copies the logs using the logs path saved on constants 
    shutil.copytree(constants.CONST_FARADAY_HOME_PATH +'/logs', path + '/logs')

def make_zip(path):
    #Makes a zip file of the new folder with all the information obtained inside
    shutil.make_archive('faraday_support', 'zip', path)

def end_config(path):
    #Deletes recursively the directory created on the init_config
    shutil.rmtree(path)

def all_for_support():
    with tqdm(total=5) as pbar:
        path = init_config()
        get_status_check(path)
        pbar.update(1)
        get_logs(path)
        pbar.update(1)
        get_pip_freeze(path)
        pbar.update(1)
        make_zip(path)
        pbar.update(1)
        end_config(path)
        pbar.update(1)

    print('[{green}+{white}] Process Completed. A {bright}faraday_support.zip{normal} was generated'
            .format(green=Fore.GREEN, white=Fore.WHITE, bright=Style.BRIGHT, normal=Style.NORMAL))