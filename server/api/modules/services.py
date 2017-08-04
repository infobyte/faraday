# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from server.utils.logger import get_logger
from server.dao.service import ServiceDAO
from server.utils.web import gzipped, validate_workspace, get_integer_parameter


services_api = Blueprint('services_api', __name__)


@services_api.route('/ws/<workspace>/services', methods=['GET'])
@gzipped
def list_services(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    services_dao = ServiceDAO(workspace)

    services = services_dao.list(service_filter=flask.request.args)

    return flask.jsonify(services)

@services_api.route('/ws/<workspace>/services/count', methods=['GET'])
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
