import os
import shutil
from os.path import join, expanduser
from pprint import pprint

try:
    # py2.7
    from configparser import ConfigParser, NoSectionError, NoOptionError
except ImportError:
    # py3
    from ConfigParser import ConfigParser, NoSectionError, NoOptionError
#from config import config

def setup_config_path():
    
    path = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.expanduser("~/.faraday/config/cscan_conf.ini")

    if os.path.exists(file_path):
        return file_path

    else:
        #TODO check if folderS exist and if not creat them
        path = os.path.join(path,"cscan_conf.ini")
        shutil.copy(path, file_path)
        return file_path

def init_config():
    
    file_path = setup_config_path()
    conf_parser = ConfigParser()
    conf_parser.read(file_path)
    config = {}
    
    for section in conf_parser.sections():
        for option in conf_parser.options(section):
            config[option] = conf_parser.get(section, option)
    return config    

pprint(init_config())
    