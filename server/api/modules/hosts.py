# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from marshmallow import Schema, fields

from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace,\
    get_integer_parameter, filter_request_args
from server.dao.host import HostDAO
from server.api.base import ReadOnlyWorkspacedView
from server.models import Host

host_api = Blueprint('host_api', __name__)


class HostSchema(Schema):
    id = fields.String(required=True, dump_only=True)
    ip = fields.String(required=True)
    description = fields.String(required=True)
    os = fields.String()


class HostsView(ReadOnlyWorkspacedView):
    route_base = 'hosts'
    model_class = Host
    schema_class = HostSchema

HostsView.register(host_api)


@gzipped
@host_api.route('/ws/<workspace>/hosts', methods=['GET'])
def list_hosts(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(flask.request.args))

    page = get_integer_parameter('page', default=0)
    page_size = get_integer_parameter('page_size', default=0)
    search = flask.request.args.get('search')
    order_by = flask.request.args.get('sort')
    order_dir = flask.request.args.get('sort_dir')

    host_filter = filter_request_args('page', 'page_size', 'search', 'sort', 'sort_dir')

    dao = HostDAO(workspace)
    result = dao.list(search=search,
                      page=page,
                      page_size=page_size,
                      order_by=order_by,
                      order_dir=order_dir,
                      host_filter=host_filter)

    return flask.jsonify(result)
