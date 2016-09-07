# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace, filter_request_args
from server.dao.command import CommandDAO

@gzipped
@app.route('/ws/<workspace>/commands', methods=['GET'])
def list_commands(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug(
        "Request parameters: {!r}".format(flask.request.args))

    commands_filter = filter_request_args()

    dao = CommandDAO(workspace)

    result = dao.list(command_filter=commands_filter)

    return flask.jsonify(result)