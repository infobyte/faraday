# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import time
import logging

from flask import request, jsonify, abort
from flask import Blueprint
from marshmallow import fields

from server.api.base import (
    AutoSchema,
    PaginatedMixin,
    ReadWriteWorkspacedView,
)
from server.models import (
    db,
    VulnerabilityGeneric,
    TagObject,
    Tag
)
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


class VulnerabilityGenericSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    website = fields.String(default='')
    _rev = fields.String(default='')
    owned = fields.Boolean(dump_only=True, default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    impact = fields.Method('get_impact')
    policyviolations = PrimaryKeyRelatedField('name', many=True,
                                              attribute='policy_violations')
    method = fields.String(default='')
    params = fields.String(default='')
    refs = PrimaryKeyRelatedField('name', many=True, attribute='references')
    issuetracker = fields.Method('get_issuetracker')
    parent = fields.Method('get_parent')
    tags = fields.Method('get_tags')
    easeofresolution = fields.String(dump_only=True, attribute='ease_of_resolution')
    hostnames = PrimaryKeyRelatedField('name', many=True)
    pname = fields.String(dump_only=True, attribute='parameter_name', default='')
    path = fields.String(default='')
    response = fields.String(default='')
    desc = fields.String(dump_only=True, attribute='description')
    obj_id = fields.String(dump_only=True, attribute='id')
    request = fields.String(default='')
    _attachments = fields.Method('get_attachments')
    target = fields.String(default='')  # TODO: review this attribute
    query = fields.String(dump_only=True, attribute='query_string', default='')
    metadata = fields.Method('get_metadata')
    service = fields.Nested(ServiceSchema(only=[
        '_id', 'ports', 'status', 'protocol', 'name', 'version', 'summary'
    ]), dump_only=True)
    host = fields.Integer(dump_only=True, attribute='host_id')

    class Meta:
        model = VulnerabilityGeneric
        fields = (
            '_id', 'status',
            'website', 'issuetracker', 'description', 'parent',
            'tags', 'severity', '_rev', 'easeofresolution', 'owned',
            'hostnames', 'pname', 'query', 'owner',
            'path', 'data', 'response', 'refs',
            'desc', 'impact', 'confirmed', 'name',
            'service', 'obj_id', 'type', 'policyviolations',
            'request', '_attachments', 'params',
            'target', 'resolution', 'method', 'metadata')

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
        if obj.host:
            return [hostname.name for hostname in obj.host.hostnames]
        if obj.service:
            return [hostname.name for hostname in obj.service.host.hostnames]
        logger.info('Vulnerability without host and service. Check invariant in obj with id {0}'.format(obj.id))
        return []

    def get_tags(self, obj):
        return [tag.name for tag in db.session.query(TagObject, Tag).filter_by(
            object_type=obj.__class__.__name__,
            object_id=obj.id
        ).all()]

    def get_parent(self, obj):
        if getattr(obj, 'service', None):
            return obj.service.id
        if getattr(obj, 'host', None):
            return obj.host.id
        return

    def get_issuetracker(self, obj):
        return {}

    def get_impact(self, obj):
        return {
            'accountability': obj.impact_accountability,
            'availability': obj.impact_availability,
            'confidentiality': obj.impact_confidentiality,
            'integrity': obj.impact_integrity
        }


class VulnerabilityView(PaginatedMixin, ReadWriteWorkspacedView):
    route_base = 'vulns'
    model_class = VulnerabilityGeneric
    schema_class = VulnerabilityGenericSchema

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
