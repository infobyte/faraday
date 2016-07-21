# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app
from server.dao.service import ServiceDAO
from server.utils.web import gzipped, validate_workspace


@app.route('/ws/<workspace>/services', methods=['GET'])
@gzipped
def list_services(workspace=None):
    validate_workspace(workspace)
    port = flask.request.args.get('port')
    try:
        port = int(port) if port is not None else None
    except:
        flask.abort(400)

    services_dao = ServiceDAO(workspace)
    services_by_host = services_dao.list(port)

    result = { 'hosts': services_by_host }

    return flask.jsonify(result)

@app.route('/ws/<workspace>/services/count', methods=['GET'])
@gzipped
def count_services(workspace=None):
    validate_workspace(workspace)
    field = flask.request.args.get('group_by')

    services_dao = ServiceDAO(workspace)
    result = services_dao.count(group_by=field)
    if result is None:
        flask.abort(400)

    return flask.jsonify(result)

