import os
import shutil

if not os.path.exists("~/.faraday/config/cscan_conf.ini"):
    path = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(path,"cscan_conf.ini")
    config_path = os.path.expanduser("~/.faraday/config/cscan_conf.ini")
    shutil.copy(path, config_path)