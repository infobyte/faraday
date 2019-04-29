#!/usr/bin/env python

# Faraday Penetration Test IDE
# Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

# Developers: the code for faraday-server is located in faraday/start_server.py

from __future__ import print_function
import sys

print(
    "From Faraday v3.8 onwards, running ./faraday-server.py doesn't work "
    "anymore. You should run faraday-server instead.\n\n"

    "This allows users to put the faraday-server script in any directory "
    "(like /usr/local/bin) and to run it from anywhere, with no need of "
    "switching to the Faraday directory.",

    file=sys.stderr
)

sys.exit(1)
