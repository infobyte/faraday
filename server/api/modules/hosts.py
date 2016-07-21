# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app
from server.utils.web import gzipped, validate_workspace, get_integer_parameter
from server.dao.host import HostDAO


@gzipped
@app.route('/ws/<workspace>/hosts', methods=['GET'])
def list_hosts(workspace=None):
    validate_workspace(workspace)
    print "REQUEST: %r" % (flask.request.args,)

    page = get_integer_parameter('page', default=0)
    page_size = get_integer_parameter('page_size', default=0)
    search = flask.request.args.get('search')
    order_by = flask.request.args.get('sort')
    order_dir = flask.request.args.get('sort_dir')

    host_filter = {}
    for arg in flask.request.args:
        if arg not in ['page', 'page_size', 'search', 'sort', 'sort_dir']:
            host_filter[arg] = flask.request.args.get(arg)

    dao = HostDAO(workspace)
    result = dao.list(search=search,
                      page=page,
                      page_size=page_size,
                      order_by=order_by,
                      order_dir=order_dir,
                      host_filter=host_filter)

    json = flask.jsonify(result)

    return json

