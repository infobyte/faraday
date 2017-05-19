from flask import request, jsonify, abort
from server.app import app
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace,\
    get_integer_parameter, filter_request_args
from server.dao.vuln import VulnerabilityDAO

@gzipped
@app.route('/ws/vulns/create_csv', methods=['GET'])
def create_csv_from_vulns(workspace=None):

    validate_workspace(workspace)

    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    cred_filter = filter_request_args()

    dao = CredentialDAO(workspace)
    result = dao.list(cred_filter=cred_filter)

    return flask.jsonify(result)
