# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
import server.dao

from server.app import app
from server.utils.web import validate_workspace


@app.route('/ws/<workspace>/services', methods=['GET'])
def list_services(workspace=None):
    validate_workspace(workspace)
    port = flask.request.args.get('port')
    try:
        port = int(port) if port is not None else None
    except:
        flask.abort(400)

    services_dao = server.dao.ServiceDAO(workspace)
    services_by_host = services_dao.list(port)

    result = { 'hosts': services_by_host }

    return flask.jsonify(result)

