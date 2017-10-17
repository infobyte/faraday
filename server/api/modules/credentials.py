# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time

import flask
from flask import Blueprint
from marshmallow import fields

from server.api.base import AutoSchema, ReadWriteWorkspacedView
from server.models import Credential
from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace, filter_request_args
from server.dao.credential import CredentialDAO


credentials_api = Blueprint('credentials_api', __name__)

class CredentialSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    _rev = fields.String(default='', dump_only=True)
    metadata = fields.Method('get_metadata')
    owned = fields.Boolean(default=False)
    owner = fields.String(dump_only=True, attribute='creator.username')
    username = fields.String(default='')
    password = fields.String(default='')
    description = fields.String(default='')

    parent = fields.Method('get_parent')

    def get_parent(self, obj):
        if getattr(obj, 'service', None):
            return obj.service.id
        if getattr(obj, 'host', None):
            return obj.host.id
        return

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
        model = Credential
        fields = ('id', '_id', 'status', 'parent',
                  'username', 'description', '_rev',
                  'owned', 'owner', 'name', 'password',
                  '_id', 'metadata')


class CredentialView(ReadWriteWorkspacedView):
    route_base = 'credentials'
    model_class = Credential
    schema_class = CredentialSchema

    def _envelope_list(self, objects, pagination_metadata=None):
        credentials = []
        for credential in objects:
            credentials.append({
                'id': credential['_id'],
                'key': credential['_id'],
                'value': credential
            })
        return {
            'credentials': credentials,
        }

CredentialView.register(credentials_api)


@gzipped
@credentials_api.route('/ws/<workspace>/credentials', methods=['GET'])
def list_credentials(workspace=None):

    validate_workspace(workspace)

    get_logger(__name__).debug(
        "Request parameters: {!r}".format(
            flask.request.args))

    cred_filter = filter_request_args()

    dao = CredentialDAO(workspace)
    result = dao.list(cred_filter=cred_filter)

    return flask.jsonify(result)
