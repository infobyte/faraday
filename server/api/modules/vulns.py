# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from flask import request, jsonify
from server.app import app
from server.utils.debug import Timer
from server.utils.web import gzipped, validate_workspace
from server.dao.vuln import VulnerabilityDAO


def get_integer_parameter(query_parameter, default=None):
    param = request.args.get(query_parameter)
    try:
        return int(param) if param is not None else default
    except ValueError:
        flask.abort(400)

@app.route('/ws/<workspace>/vulns', methods=['GET'])
@gzipped
def get_vulnerabilities(workspace=None):
    validate_workspace(workspace)

    print "REQUEST: %r" % (request.args,)

    page = get_integer_parameter('page', default=0)
    page_size = get_integer_parameter('page_size', default=0)
    search = request.args.get('search')
    order_by = request.args.get('sort')
    order_dir = request.args.get('sort_dir')

    vuln_filter = {}
    for arg in request.args:
        if arg not in ['page', 'page_size', 'search', 'sort', 'sort_dir']:
            vuln_filter[arg] = request.args.get(arg)

    vuln_dao = VulnerabilityDAO(workspace)

    with Timer('query'):
        result = vuln_dao.list(search=search,
                               page=page,
                               page_size=page_size,
                               order_by=order_by,
                               order_dir=order_dir,
                               vuln_filter=vuln_filter)

    with Timer('jsonify'):
        json = flask.jsonify(result)

    return json

@app.route('/ws/<workspace>/vulns/count', methods=['GET'])
@gzipped
def count_vulnerabilities(workspace=None):
    validate_workspace(workspace)

    field = request.args.get('group_by')
    search = request.args.get('search')
    vuln_filter = {}
    for arg in request.args:
        if arg not in ['search', 'group_by']:
            vuln_filter[arg] = request.args.get(arg)

    vuln_dao = VulnerabilityDAO(workspace)
    result = vuln_dao.count(group_by=field, search=search, vuln_filter=vuln_filter)
    if result is None:
        flask.abort(400)

    return flask.jsonify(result)

