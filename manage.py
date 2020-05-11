#!/usr/bin/env python

# Faraday Penetration Test IDE
# Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

# Developers: the code for faraday-manage is located in faraday/manage.py
from __future__ import absolute_import

from __future__ import print_function
import sys

print(
    "From Faraday v3.8 onwards, running ./manage.py doesn't work anymore. "
    "You should run faraday-manage instead.\n\n"

    "This allows users to put the faraday-manage script in any directory "
    "(like /usr/local/bin) and to run it from anywhere, with no need of "
    "switching to the Faraday directory.",

    file=sys.stderr
)

sys.exit(1)



# I'm Py3
