# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace,\
    get_integer_parameter, filter_request_args, get_mandatory_integer_parameter

from server.dao.interface import InterfaceDAO


@gzipped
@app.route('/ws/<workspace>/interfaces', methods=['GET'])
def list_interfaces(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    host_id = get_mandatory_integer_parameter('host')

    dao = InterfaceDAO(workspace)
    result = dao.list(host_id=host_id)

    return flask.jsonify(result)

