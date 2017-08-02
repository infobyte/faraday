# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.web import app
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace, filter_request_args, get_integer_parameter
from server.dao.command import CommandDAO

@gzipped
@app.route('/ws/<workspace>/commands', methods=['GET'])
def list_commands(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug(
        "Request parameters: {!r}".format(flask.request.args))

    page = get_integer_parameter('page', default=0)
    page_size = get_integer_parameter('page_size', default=0)

    commands_filter = filter_request_args(
        'page', 'page_size')

    dao = CommandDAO(workspace)
    result = dao.list(
        page=page,
        page_size=page_size,
        command_filter=commands_filter)

    return flask.jsonify(result)
