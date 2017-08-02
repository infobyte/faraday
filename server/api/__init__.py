# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os.path
import glob
import sys

# Add handlers modules directory to sys.path
modules_path = os.path.join(os.path.dirname(__file__), 'modules')
sys.path.append(modules_path)

# Get modules path, compiled or not
modules_files = glob.glob(os.path.join(modules_path, '*.py'))
modules_files += glob.glob(os.path.join(modules_path, '*.pyc'))

# Remove duplicate names
extract_module_name = lambda module_path: os.path.splitext(os.path.basename(module_path))[0]
modules = set(map(extract_module_name, modules_files))

# Import and add to handlers namespace every module found in modules
for handler_name in modules:
    globals()[handler_name] = __import__(handler_name)


def get_handlers():
    return BaseHandler.BaseHandler.get_handlers()
