# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import time
import logging
from base64 import b64encode, b64decode

from filteralchemy import FilterSet, operators
from flask import request
from flask import Blueprint
from marshmallow import fields, post_load, ValidationError

from depot.manager import DepotManager
from server.api.base import (
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
    PaginatedMixin,
    ReadWriteWorkspacedView,
)
from server.fields import FaradayUploadedFile
from server.models import (
    db,
    Tag,
    TagObject,
    Vulnerability,
    VulnerabilityWeb,
    VulnerabilityGeneric,
    Host, Service, File, Reference, PolicyViolation)
from server.utils.database import get_or_create

from server.api.modules.services import ServiceSchema
from server.schemas import PrimaryKeyRelatedField

vulns_api = Blueprint('vulns_api', __name__)
logger = logging.getLogger(__name__)


class EvidenceSchema(AutoSchema):
    content_type = fields.Method('get_content_type')
    data = fields.Method('get_data')

    class Meta:
        model = File
        fields = (
            'content_type',
            'data'
        )

    def get_content_type(self, file_obj):
        depot = DepotManager.get()
        return depot.get(file_obj.content.get('file_id')).content_type

    def get_data(self, file_obj):
        depot = DepotManager.get()
        return b64encode(depot.get(file_obj.content.get('file_id')).read())


class VulnerabilitySchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')

    _rev = fields.String(default='')
    _attachments = fields.Method('get_attachments')
    owned = fields.Boolean(dump_only=True, default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    impact = fields.Method('get_impact', deserialize='load_impact')
    policyviolations = PrimaryKeyRelatedField('name', many=True,
                                              attribute='policy_violations', default=[])
    desc = fields.String(dump_only=True, attribute='description')
    refs = PrimaryKeyRelatedField('name', many=True, attribute='references', default=[])
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
    status = fields.Method('get_status', deserialize='load_status')
    type = fields.Method('get_type', deserialize='load_type')
    obj_id = fields.String(dump_only=True, attribute='id')
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
        res = []
        files = db.session.query(File).filter_by(object_id=obj.id, object_type=obj.__class__.__name__).all()

        for file_obj in files:
            ret, errors = EvidenceSchema().dump(file_obj)
            if errors:
                raise ValidationError(errors, data=ret)
            res.append(ret)

        return res

    def get_hostnames(self, obj):
        # TODO: improve performance here
        # TODO: move this to models?
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

    def get_status(self, obj):
        return obj.status

    def get_impact(self, obj):
        return {
            'accountability': obj.impact_accountability,
            'availability': obj.impact_availability,
            'confidentiality': obj.impact_confidentiality,
            'integrity': obj.impact_integrity,
        }

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


# Use this override for filterset fields that filter by en exact match by
# default, and not by a similar one (like operator)
_strict_filtering = {'default_operator': operators.Equal}

class VulnerabilityFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = VulnerabilityWeb  # It has all the fields
        # TODO migration: Check if we should add fields creator, owner, command,
        # impact, type, service, issuetracker, tags, date, target, host,
        # easeofresolution, evidence, policy violations, hostnames, target
        fields = (
            "status", "website", "parameter_name", "query_string", "path",
            "data", "severity", "confirmed", "name", "request", "response",
            "parameters", "resolution", "method", "ease_of_resolution",
            "description")
        strict_fields = (
            "severity", "confirmed", "method"
        )
        default_operator = operators.ILike
        column_overrides = {
            field: _strict_filtering for field in strict_fields}
        operators = (operators.ILike, operators.Equal)


class VulnerabilityView(PaginatedMixin,
                        FilterAlchemyMixin,
                        ReadWriteWorkspacedView):
    route_base = 'vulns'
    filterset_class = VulnerabilityFilterSet

    model_class_dict = {
        'Vulnerability': Vulnerability,
        'VulnerabilityWeb': VulnerabilityWeb,
        'VulnerabilityGeneric': VulnerabilityGeneric,
    }
    schema_class_dict = {
        'Vulnerability': VulnerabilitySchema,
        'VulnerabilityWeb': VulnerabilityWebSchema
    }

    def _perform_create(self, data, **kwargs):
        data = self._parse_data(self._get_schema_class()(strict=True),
                                request)
        attachments = data.pop('_attachments')
        references = data.pop('references')
        policyviolations = data.pop('policy_violations')
        obj = super(VulnerabilityView, self)._perform_create(data, **kwargs)

        for reference in references:
            instance, _ = get_or_create(db.session, Reference, name=reference, workspace=self.workspace)
            obj.references.append(instance)

        for policyviolation in policyviolations:
            instance, _ = get_or_create(db.session, PolicyViolation, name=policyviolation, workspace=self.workspace)
            obj.policy_violations.append(instance)

        for filename, attachment in attachments.items():
            faraday_file = FaradayUploadedFile(b64decode(attachment['data']))
            get_or_create(
                db.session,
                File,
                object_id=obj.id,
                object_type=obj.__class__.__name__,
                name = os.path.splitext(os.path.basename(filename))[0],
                filename = os.path.basename(filename),
                content=faraday_file,
            )
        return obj

    @property
    def model_class(self):
        if request.method == 'POST':
            return self.model_class_dict[request.json['type']]
        # We use Generic to list all vulns from all types
        return self.model_class_dict['VulnerabilityGeneric']

    def _get_schema_class(self):
        assert self.schema_class_dict is not None, "You must define schema_class"
        if request.method == 'POST':
            return self.schema_class_dict[request.json['type']]
        # We use web since it has all the fields
        return self.schema_class_dict['VulnerabilityWeb']

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
