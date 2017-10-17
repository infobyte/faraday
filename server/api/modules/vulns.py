# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time
import logging

from flask import request, jsonify, abort
from flask import Blueprint
from marshmallow import fields, post_load

from server.api.base import (
    AutoSchema,
    PaginatedMixin,
    ReadWriteWorkspacedView,
)
from server.models import (
    db,
    Tag,
    TagObject,
    Vulnerability,
    VulnerabilityWeb,
    VulnerabilityGeneric,
    Host, Service)
from server.utils.logger import get_logger
from server.utils.web import (
    gzipped,
    validate_workspace,
    get_integer_parameter,
    filter_request_args
)
from server.api.modules.services import ServiceSchema
from server.schemas import PrimaryKeyRelatedField
from server.dao.vuln import VulnerabilityDAO

vulns_api = Blueprint('vulns_api', __name__)
logger = logging.getLogger(__name__)


class VulnerabilitySchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')

    _rev = fields.String(default='')
    _attachments = fields.Method(load_only=True, deserialize='load_attachments')
    owned = fields.Boolean(dump_only=True, default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    impact = fields.Method(deserialize='load_impact')
    policyviolations = PrimaryKeyRelatedField('name', many=True,
                                              attribute='policy_violations')
    desc = fields.String(dump_only=True, attribute='description')
    refs = PrimaryKeyRelatedField('name', many=True, attribute='references')
    issuetracker = fields.Method('get_issuetracker')
    parent = fields.Method('get_parent', deserialize='load_parent')
    parent_type = fields.Method('get_parent_type')
    tags = fields.Method('get_tags')
    easeofresolution = fields.String(dump_only=True, attribute='ease_of_resolution')
    hostnames = PrimaryKeyRelatedField('name', many=True)
    metadata = fields.Method('get_metadata')
    service = fields.Nested(ServiceSchema(only=[
        '_id', 'ports', 'status', 'protocol', 'name', 'version', 'summary'
    ]), dump_only=True)
    host = fields.Integer(dump_only=True, attribute='host_id')
    status = fields.Method(attribute='status', deserialize='load_status')
    type = fields.Method('get_type', deserialize='load_type')
    obj_id = fields.String(dump_only=True, attribute='id')
    _attachments = fields.Method('get_attachments')
    target = fields.String(default='')  # TODO: review this attribute

    class Meta:
        model = Vulnerability
        fields = (
            '_id', 'status',
            'issuetracker', 'description', 'parent', 'parent_type',
            'tags', 'severity', '_rev', 'easeofresolution', 'owned',
            'hostnames', 'owner',
            'data', 'refs',
            'desc', 'impact', 'confirmed', 'name',
            'service', 'obj_id', 'type', 'policyviolations',
            '_attachments',
            'target', 'resolution', 'metadata')

    def get_type(self, obj):
        return obj.__class__.__name__

    def get_parent_type(self, obj):
        return obj.parent_type

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

    def get_attachments(self, obj):
        # TODO: retrieve obj attachments
        return []

    def get_hostnames(self, obj):
        # TODO: improve performance here
        if obj.host:
            return [hostname.name for hostname in obj.host.hostnames]
        if obj.service:
            return [hostname.name for hostname in obj.service.host.hostnames]
        logger.info('Vulnerability without host and service. Check invariant in obj with id {0}'.format(obj.id))
        return []

    def get_tags(self, obj):
        # TODO: improve performance here
        return [tag.name for tag in db.session.query(TagObject, Tag).filter_by(
            object_type=obj.__class__.__name__,
            object_id=obj.id
        ).all()]

    def get_parent(self, obj):
        return obj.parent.id

    def get_issuetracker(self, obj):
        return {}

    def load_impact(self, value):
        pass

    def load_status(self, value):
        if value == 'opened':
            return 'open'

    def load_type(self, value):
        if value == 'Vulnerability':
            return 'vulnerability'
        if value == 'VulnerabilityWeb':
            return 'vulnerability_web'

    def load_parent(self, value):
        self.parent_id = value
        return value

    def load_attachments(self, value):
        # TODO: implement attachments
        pass

    @post_load
    def clean_up(self, data):
        data.pop('_attachments')
        return data

    @post_load
    def set_impact(self, data):
        impact = data.pop('impact')
        if impact:
            pass
        return data


    @post_load
    def set_parent(self, data):
        # schema guarantees that parent_type exists.
        parent_class = None
        parent_type = data.pop('parent_type')
        parent_id = data.pop('parent')
        if parent_type == 'Host':
            parent_class = Host
            parent_field = 'host_id'
        if parent_type == 'Service':
            parent_class = Service
            parent_field = 'service_id'
        if not parent_class:
            raise Exception('Bad data')

        parent = db.session.query(parent_class).filter_by(id=parent_id).first()
        if not parent:
            raise Exception('Parent not found')
        data[parent_field] = parent.id
        return data


class VulnerabilityWebSchema(VulnerabilitySchema):

    method = fields.String(default='')
    params = fields.String(attribute='parameters', default='')
    pname = fields.String(dump_only=True, attribute='parameter_name', default='')
    path = fields.String(default='')
    response = fields.String(default='')
    request = fields.String(default='')
    website = fields.String(default='')
    query = fields.String(dump_only=True, attribute='query_string', default='')

    class Meta:
        model = VulnerabilityWeb
        fields = (
            '_id', 'status', 'parent_type',
            'website', 'issuetracker', 'description', 'parent',
            'tags', 'severity', '_rev', 'easeofresolution', 'owned',
            'hostnames', 'pname', 'query', 'owner',
            'path', 'data', 'response', 'refs',
            'desc', 'impact', 'confirmed', 'name',
            'service', 'obj_id', 'type', 'policyviolations',
            'request', '_attachments', 'params',
            'target', 'resolution', 'method', 'metadata')


class VulnerabilityView(PaginatedMixin, ReadWriteWorkspacedView):
    route_base = 'vulns'

    model_class_dict = {
        'Vulnerability': Vulnerability,
        'VulnerabilityWeb': VulnerabilityWeb,
        'VulnerabilityGeneric': VulnerabilityGeneric,
    }
    schema_class = {
        'Vulnerability': VulnerabilitySchema,
        'VulnerabilityWeb': VulnerabilityWebSchema
    }

    @property
    def model_class(self):
        if request.method == 'POST':
            return self.model_class_dict[request.json['type']]
        return self.model_class_dict['VulnerabilityGeneric']

    def _get_schema_class(self):
        assert self.schema_class is not None, "You must define schema_class"
        if request.method == 'POST':
            return self.schema_class[request.json['type']]
        return self.schema_class['VulnerabilityWeb']

    def _envelope_list(self, objects, pagination_metadata=None):
        vulns = []
        for vuln in objects:
            vulns.append({
                'id': vuln['_id'],
                'key': vuln['_id'],
                'value': vuln
            })
        return {
            'vulnerabilities': vulns,
        }

VulnerabilityView.register(vulns_api)


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
