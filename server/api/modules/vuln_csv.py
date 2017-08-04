from flask import jsonify
from flask import Blueprint

from server.utils.logger import get_logger
from server.utils.web import (
    gzipped,
    validate_workspace,
    filter_request_args,
)
from server.dao.credential import CredentialDAO

vuln_csv_api = Blueprint('vuln_csv_api', __name__)


@gzipped
@vuln_csv_api.route('/ws/vulns/create_csv', methods=['GET'])
def create_csv_from_vulns(workspace=None):

    validate_workspace(workspace)

    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    cred_filter = filter_request_args()

    dao = CredentialDAO(workspace)
    result = dao.list(cred_filter=cred_filter)

    return jsonify(result)
