import os
import sys
import shutil
import config.constant as constants 
from server.commands import status_check 
try:
    from pip._internal.operations import freeze
except ImportError:  # pip < 10.0
    from pip.operations import freeze

def init_config():
    #Creates the directory where all the info will go to
    os.makedirs('faraday_support')

def get_status_check():
    #Executes status check from with-in the code and uses stdout to save info to file
    #stdout was the only way to get this information without doing a big refactor
    original_stdout = sys.stdout

    sys.stdout = open('faraday_support/status_check.txt','wt')
    status_check.full_status_check()
    
    sys.stdout.close()
    sys.stdout = original_stdout


def get_pip_freeze():
    #Executes pip freeze internally and saves the info a pip_freeze.txt file
    x = freeze.freeze()
    pip_file = open('faraday_support/pip_freeze.txt', 'a')
    for p in x:
        pip_file.write(p)
    pip_file.close()

def get_logs():
    #Copies the logs using the logs path saved on constants 
    shutil.copytree(constants.CONST_FARADAY_HOME_PATH +'/logs','faraday_support/logs')

def make_zip():
    #Makes a zip file of the new folder with all the information obtained inside
    shutil.make_archive('faraday_support', 'zip', 'faraday_support')


def end_config():
    #Deletes recursively the directory created on the init_config
    shutil.rmtree('faraday_support')

def all_for_support():
    init_config()
    get_status_check()
    get_logs()
    get_pip_freeze()
    make_zip()
    end_config()