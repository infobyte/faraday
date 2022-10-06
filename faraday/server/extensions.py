"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Related third party imports
from flask_socketio import SocketIO

socketio = SocketIO(path='/wsocket/v1')
