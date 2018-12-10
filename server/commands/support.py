import os
import sys
import shutil
import tempfile
import config.constant as constants 
from server.commands import status_check 
try:
    from pip._internal.operations import freeze
except ImportError:  # pip < 10.0
    from pip.operations import freeze

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
    x = freeze.freeze()
    pip_file = open(path + '/pip_freeze.txt', 'a')
    for p in x:
        pip_file.write(p)
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
    path = init_config()
    get_status_check(path)
    get_logs(path)
    get_pip_freeze(path)
    make_zip(path)
    end_config(path)