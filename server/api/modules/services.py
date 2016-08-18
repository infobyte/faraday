# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app
from server.utils.logger import get_logger
from server.dao.service import ServiceDAO
from server.utils.web import gzipped, validate_workspace, get_integer_parameter


@app.route('/ws/<workspace>/services', methods=['GET'])
@gzipped
def list_services(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    services_dao = ServiceDAO(workspace)
    interface_id = flask.request.args.get('interface_id')
    if interface_id:
        services_by_parent = services_dao.get_services_by_parent(interface_id)
        return flask.jsonify(services_by_parent)

    port = get_integer_parameter('port', default=None)

    services_by_host = services_dao.list(port)

    result = { 'hosts': services_by_host }

    return flask.jsonify(result)

@app.route('/ws/<workspace>/services/count', methods=['GET'])
@gzipped
def count_services(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    field = flask.request.args.get('group_by')

    services_dao = ServiceDAO(workspace)
    result = services_dao.count(group_by=field)
    if result is None:
        flask.abort(400)

    return flask.jsonify(result)

