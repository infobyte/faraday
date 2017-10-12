# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time

import flask
from flask import Blueprint
from marshmallow import fields

from server.api.base import AutoSchema, ReadWriteWorkspacedView
from server.models import Service
from server.utils.logger import get_logger
from server.dao.service import ServiceDAO
from server.utils.web import gzipped, validate_workspace, get_integer_parameter


services_api = Blueprint('services_api', __name__)


class ServiceSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    _rev = fields.String(default='', dump_only=True)
    metadata = fields.Method('get_metadata')
    owned = fields.Boolean(default=False)
    owner = fields.String(dump_only=True, attribute='creator.username')
    ports = fields.Method(attribute='port', deserialize='load_port')
    status = fields.String(default='open')
    parent = fields.Method(attribute='host_id', deserialize='load_host_id', load_only=True)

    def load_host_id(self, value):
        return value

    def load_port(self, value):
        return str(value.pop())

    def get_metadata(self, obj):
        return {
            "command_id": "e1a042dd0e054c1495e1c01ced856438",
            "create_time": time.mktime(obj.create_date.utctimetuple()),
            "creator": "Metasploit",
            "owner": "", "update_action": 0,
            "update_controller_action": "No model controller call",
            "update_time": time.mktime(obj.update_date.utctimetuple()),
            "update_user": ""
        }

    class Meta:
        model = Service
        fields = ('_id', 'status', 'parent',
                  'protocol', 'description', '_rev',
                  'owned', 'owner', 'credentials',
                  'name', 'version', '_id', 'ports',
                  'metadata')


class ServiceView(ReadWriteWorkspacedView):
    route_base = 'services'
    model_class = Service
    schema_class = ServiceSchema

    def _envelope_list(self, objects, pagination_metadata=None):
        services = []
        for service in objects:
            services.append({
                'id': service['_id'],
                'key': service['_id'],
                'value': service
            })
        return {
            'services': services,
        }

ServiceView.register(services_api)


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
