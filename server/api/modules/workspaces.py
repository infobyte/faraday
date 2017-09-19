# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import json

import flask
from flask import Blueprint
from marshmallow import fields

from server.models import db, Workspace
from server.dao.host import HostDAO
from server.dao.vuln import VulnerabilityDAO
from server.dao.service import ServiceDAO
from server.dao.workspace import WorkspaceDAO
from server.utils.logger import get_logger
from server.utils.web import (
    build_bad_request_response,
    filter_request_args,
    get_basic_auth,
    get_integer_parameter,
    gzipped,
    validate_admin_perm,
    validate_workspace
)
from server.couchdb import (
    list_workspaces_as_user,
    get_workspace
)
from server.api.base import ReadWriteView, AutoSchema

workspace_api = Blueprint('workspace_api', __name__)


class WorkspaceSchema(AutoSchema):

    host_count = fields.Integer(dump_only=True)

    class Meta:
        model = Workspace
        fields = ('id', 'customer', 'description', 'active', 'start_date',
                  'end_date', 'name', 'public', 'scope', 'host_count')


class WorkspaceView(ReadWriteView):
    route_base = 'workspaces'
    model_class = Workspace
    schema_class = WorkspaceSchema

WorkspaceView.register(workspace_api)


@workspace_api.route('/ws', methods=['GET'])
@gzipped
def workspace_list():
    get_logger(__name__).debug("Request parameters: {!r}"
        .format(flask.request.args))

    page = get_integer_parameter('page', default=0)
    page_size = get_integer_parameter('page_size', default=0)
    search = flask.request.args.get('search')
    order_by = flask.request.args.get('sort')
    order_dir = flask.request.args.get('sort_dir')

    ws_filter = filter_request_args('page', 'page_size', 'search', 'sort', 'sort_dir')

    ws_dao = WorkspaceDAO()

    result = ws_dao.list(search=search,
                           page=page,
                           page_size=page_size,
                           order_by=order_by,
                           order_dir=order_dir,
                           workspace_filter=ws_filter)

    return flask.jsonify(result)


@workspace_api.route('/ws/<workspace>/summary', methods=['GET'])
@gzipped
def workspace_summary(workspace=None):
    validate_workspace(workspace)

    services_count = ServiceDAO(workspace).count()
    vuln_count = VulnerabilityDAO(workspace).count(vuln_filter=flask.request.args)
    host_count = HostDAO(workspace).count()

    response = {
        'stats': {
            'services':    services_count.get('total_count', 0),
            'total_vulns': vuln_count.get('total_count', 0),
            'web_vulns':   vuln_count.get('web_vuln_count', 0),
            'std_vulns':   vuln_count.get('vuln_count', 0),
            'hosts':       host_count.get('total_count', 0),
        }
    }

    return flask.jsonify(response)


@workspace_api.route('/ws/<workspace>', methods=['GET'])
@gzipped
def workspace(workspace):
    validate_workspace(workspace)
    workspaces = list_workspaces_as_user(
        flask.request.cookies, get_basic_auth())['workspaces']
    if not workspaces:
        return flask.abort(404)
    ws = get_workspace(workspace, flask.request.cookies, get_basic_auth()) if workspace in workspaces else None
    # TODO: When the workspace DAO is ready, we have to remove this next line
    if not ws.get('fdate') and ws.get('duration'):
        ws['fdate'] = ws.get('duration').get('end')
    if not ws.get('description'):
        ws['description'] = ''
    return flask.jsonify(ws)


@workspace_api.route('/ws/<workspace>', methods=['PUT'])
@gzipped
def workspace_create_or_update(workspace):
    # only admins can create workspaces
    validate_admin_perm()

    try:
        document = json.loads(flask.request.data)
    except ValueError:
        return build_bad_request_response('invalid json')
    if not document.get('name', None):
        return build_bad_request_response('workspace name needed')
    if document.get('name') != workspace:
        return build_bad_request_response('workspace name and route parameter don\'t match')
    if document.get('name').startswith('_'):
        return build_bad_request_response('database cannot start with an underscore')
    document['_id'] = document.get('name')  # document dictionary does not have id, add it
    workspace_exists = db.session.query(Workspace).filter_by(name=workspace).first()
    if not workspace_exists:
        new_workspace = Workspace(name=workspace)
        db.session.add(new_workspace)
        db.session.commit()
        res = True
    else:
        response = flask.jsonify({'error': "Workspace {0} already exists.".format(workspace)})
        response.status_code = 409
        return response

    if not res:
        response = flask.jsonify({'error': "There was an error {0} the workspace".format("updating" if is_update_request else "creating")})
        response.status_code = 500
        return response

    return flask.jsonify({'ok': True})


@workspace_api.route('/ws/<workspace>', methods=['DELETE'])
@gzipped
def workspace_delete(workspace):
    # only admins can delete workspaces
    validate_admin_perm()
    validate_workspace(workspace)

    db_manager = get_manager()

    if not db_manager.delete_workspace(workspace):
        response = flask.jsonify({'error': "There was an error deleting the workspace"})
        response.status_code = 500
        return response

    return flask.jsonify({'ok': True})
