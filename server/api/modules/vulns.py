# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from flask import request, jsonify, abort
from flask import Blueprint
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace,\
    get_integer_parameter, filter_request_args
from server.dao.vuln import VulnerabilityDAO

vulns_api = Blueprint('vulns_api', __name__)


@vulns_api.route('/ws/<workspace>/vulns', methods=['GET'])
@gzipped
def get_vulnerabilities(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(request.args))

    page = get_integer_parameter('page', default=0)
    page_size = get_integer_parameter('page_size', default=0)
    search = request.args.get('search')
    order_by = request.args.get('sort')
    order_dir = request.args.get('sort_dir')

    vuln_filter = filter_request_args(
        'page', 'page_size', 'search', 'sort', 'sort_dir')

    vuln_dao = VulnerabilityDAO(workspace)

    result = vuln_dao.list(search=search,
                           page=page,
                           page_size=page_size,
                           order_by=order_by,
                           order_dir=order_dir,
                           vuln_filter=vuln_filter)

    return jsonify(result)


@vulns_api.route('/ws/<workspace>/vulns/count', methods=['GET'])
@gzipped
def count_vulnerabilities(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(request.args))

    field = request.args.get('group_by')
    search = request.args.get('search')
    vuln_filter = filter_request_args('search', 'group_by')

    vuln_dao = VulnerabilityDAO(workspace)
    result = vuln_dao.count(group_by=field,
                            search=search,
                            vuln_filter=vuln_filter)
    if result is None:
        abort(400)

    return jsonify(result)
