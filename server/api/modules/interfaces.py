# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint

from server.utils.logger import get_logger
from server.utils.web import (
    gzipped,
    validate_workspace,
)

from server.dao.interface import InterfaceDAO

interfaces_api = Blueprint('interface_api', __name__)


@gzipped
@interfaces_api.route('/ws/<workspace>/interfaces', methods=['GET'])
def list_interfaces(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}".format(flask.request.args))

    dao = InterfaceDAO(workspace)
    result = dao.list(interface_filter=flask.request.args)

    return flask.jsonify(result)
