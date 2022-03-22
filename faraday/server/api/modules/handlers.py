"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

"""

# Related third party imports
from flask import jsonify, Blueprint

handlers_api = Blueprint('handlers_api', __name__)


@handlers_api.errorhandler(500)
def error_response(e):
    return jsonify({
        'messages': 'error',
    }), 500

# .register(commandsrun_api)
