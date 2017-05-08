# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace, filter_request_args
from server.dao.credential import CredentialDAO


@gzipped
@app.route('/ws/<workspace>/credentials', methods=['GET'])
def list_credentials(workspace=None):

    validate_workspace(workspace)

    get_logger(__name__).debug(
        "Request parameters: {!r}".format(
            flask.request.args))

    cred_filter = filter_request_args()

    dao = CredentialDAO(workspace)
    result = dao.list(cred_filter=cred_filter)

    return flask.jsonify(result)
