import os
import shutil

for section in config.sections():
    dictionary[section] = {}
    for option in config.options(section):
        dictionary[section][option] = config.get(section, option)
