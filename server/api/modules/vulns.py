# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import time
import logging
from base64 import b64encode, b64decode

from filteralchemy import FilterSet, operators
from flask import request, current_app
from flask import Blueprint
from marshmallow import Schema, fields, post_load, ValidationError
from marshmallow.validate import OneOf
from sqlalchemy import and_
from sqlalchemy.orm import joinedload, selectin_polymorphic
from sqlalchemy.orm.exc import NoResultFound

from depot.manager import DepotManager
from server.api.base import (
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
    PaginatedMixin,
    ReadWriteWorkspacedView,
    InvalidUsage)
from server.fields import FaradayUploadedFile
from server.models import (
    db,
    CommandObject,
    File,
    Host,
    Service,
    Vulnerability,
    VulnerabilityWeb,
    VulnerabilityGeneric,
    Workspace
)
from server.utils.database import get_or_create

from server.api.modules.services import ServiceSchema
from server.schemas import (
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
    MetadataSchema)

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


class ImpactSchema(Schema):
    accountability = fields.Boolean(attribute='impact_accountability')
    availability = fields.Boolean(attribute='impact_availability')
    confidentiality = fields.Boolean(attribute='impact_confidentiality')
    integrity = fields.Boolean(attribute='impact_integrity')


class VulnerabilitySchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')

    _rev = fields.String(dump_only=True, default='')
    _attachments = fields.Method(serialize='get_attachments', deserialize='load_attachments', default=[])
    owned = fields.Boolean(dump_only=True, default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    impact = SelfNestedField(ImpactSchema())
    desc = fields.String(attribute='description')
    policyviolations = fields.List(fields.String,
                                   attribute='policy_violations')
    refs = fields.List(fields.String(), attribute='references')
    issuetracker = fields.Method(serialize='get_issuetracker')
    parent = fields.Method(serialize='get_parent', deserialize='load_parent', required=True)
    parent_type = MutableField(fields.Method('get_parent_type'),
                               fields.String(),
                               required=True)
    tags = PrimaryKeyRelatedField('name', dump_only=True, many=True)
    easeofresolution = fields.String(attribute='ease_of_resolution', validate=OneOf(Vulnerability.EASE_OF_RESOLUTIONS),)
    hostnames = PrimaryKeyRelatedField('name', many=True, dump_only=True)
    service = fields.Nested(ServiceSchema(only=[
        '_id', 'ports', 'status', 'protocol', 'name', 'version', 'summary'
    ]), dump_only=True)
    host = fields.Integer(dump_only=True, attribute='host_id')
    severity = fields.Method(serialize='get_severity', deserialize='load_severity')
    status = fields.Method(serialize='get_status', deserialize='load_status')  # TODO: this breaks enum validation.
    type = fields.Method(serialize='get_type', deserialize='load_type', required=True)
    obj_id = fields.String(dump_only=True, attribute='id')
    target = fields.Method('get_target')
    metadata = SelfNestedField(MetadataSchema())
    date = fields.DateTime(attribute='create_date',
                           dump_only=True)  # This is only used for sorting

    class Meta:
        model = Vulnerability
        fields = (
            '_id', 'status',
            'issuetracker', 'description', 'parent', 'parent_type',
            'tags', 'severity', '_rev', 'easeofresolution', 'owned',
            'hostnames', 'owner',
            'date', 'data', 'refs',
            'desc', 'impact', 'confirmed', 'name',
            'service', 'obj_id', 'type', 'policyviolations',
            '_attachments',
            'target', 'resolution', 'metadata')

    def get_type(self, obj):
        return obj.__class__.__name__

    def get_attachments(self, obj):
        res = []

        for file_obj in obj.evidence:
            ret, errors = EvidenceSchema().dump(file_obj)
            if errors:
                raise ValidationError(errors, data=ret)
            res.append(ret)

        return res

    def load_attachments(self, value):
        return value

    def get_parent(self, obj):
        return obj.service_id or obj.host_id

    def get_parent_type(self, obj):
        assert obj.service_id is not None or obj.host_id is not None
        return 'Service' if obj.service_id is not None else 'Host'

    def get_severity(self, obj):
        if obj.severity == 'medium':
            return 'med'
        if obj.severity == 'informational':
            return 'info'
        return obj.severity

    def get_status(self, obj):
        if obj.status == 'open':
            return 'opened'
        return obj.status

    def get_issuetracker(self, obj):
        return {}

    def get_target(self, obj):
        if obj.service is not None:
            return obj.service.host.ip
        else:
            return obj.host.ip

    def load_severity(self, value):
        if value == 'med':
            return 'medium'
        if value == 'info':
            return 'informational'
        return value

    def load_status(self, value):
        if value == 'opened':
            return 'open'
        return value

    def load_type(self, value):
        if value == 'Vulnerability':
            return 'vulnerability'
        if value == 'VulnerabilityWeb':
            return 'vulnerability_web'

    def load_parent(self, value):
        return value

    @post_load
    def post_load_impact(self, data):
        # Unflatten impact (move data[impact][*] to data[*])
        impact = data.pop('impact', None)
        if impact:
            data.update(impact)
        return data

    @post_load
    def post_load_parent(self, data):
        # schema guarantees that parent_type exists.
        parent_class = None
        parent_type = data.pop('parent_type', None)
        parent_id = data.pop('parent', None)
        if not (parent_type and parent_id):
            # Probably a partial load, since they are required
            return
        if parent_type == 'Host':
            parent_class = Host
            parent_field = 'host_id'
        if parent_type == 'Service':
            parent_class = Service
            parent_field = 'service_id'
        if not parent_class:
            print('parent_type', parent_type)
            raise ValidationError('Unknown parent type')

        try:
            parent = db.session.query(parent_class).join(Workspace).filter(
                Workspace.name == self.context['workspace_name'],
                parent_class.id == parent_id
            ).one()
        except NoResultFound:
            raise ValidationError('Parent id not found: {}'.format(parent_id))
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
            'path', 'date', 'data', 'response', 'refs',
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
        # TODO migration: Check if we should add fields creator, owner,
        # command, impact, type, service, issuetracker, tags, date, target,
        # host, easeofresolution, evidence, policy violations, hostnames,
        # target
        fields = (
            "status", "website", "parameter_name", "query_string", "path",
            "data", "severity", "confirmed", "name", "request", "response",
            "parameters", "resolution", "method", "ease_of_resolution",
            "description", "command_id")

        strict_fields = (
            "severity", "confirmed", "method"
        )

        default_operator = operators.ILike
        column_overrides = {
            field: _strict_filtering for field in strict_fields}
        operators = (operators.ILike, operators.Equal)

    def filter(self):
        """Generate a filtered query from request parameters.

        :returns: Filtered SQLALchemy query
        """
        command_id = request.args.get('command_id')
        if command_id:
            self.query = db.session.query(VulnerabilityGeneric).join(CommandObject, and_(VulnerabilityWeb.id == CommandObject.object_id, CommandObject.object_type=='vulnerability'))

        query = super(VulnerabilityFilterSet, self).filter()

        if command_id:
            query = query.filter(CommandObject.command_id==int(command_id))
        return query


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
        data = self._parse_data(self._get_schema_instance(kwargs),
                                request)
        # TODO migration: use default values when popping and validate the
        # popped object has the expected type.
        attachments = data.pop('_attachments', {})

        # This will be set after setting the workspace
        references = data.pop('references')
        policyviolations = data.pop('policy_violations')

        obj = super(VulnerabilityView, self)._perform_create(data, **kwargs)
        obj.references = references
        obj.policy_violations = policyviolations

        for filename, attachment in attachments.items():
            faraday_file = FaradayUploadedFile(b64decode(attachment['data']))
            get_or_create(
                db.session,
                File,
                object_id=obj.id,
                object_type='vulnerability',
                name=os.path.splitext(os.path.basename(filename))[0],
                filename=os.path.basename(filename),
                content=faraday_file,
            )
        db.session.commit()
        return obj

    def _get_eagerloaded_query(self, *args, **kwargs):
        """Eager hostnames loading.

        This is too complex to get_joinedloads so I have to
        override the function
        """
        query = super(VulnerabilityView, self)._get_eagerloaded_query(
            *args, **kwargs)
        joinedloads = [
            joinedload(Vulnerability.host)
            .load_only(Host.id)  # Only hostnames are needed
            .joinedload(Host.hostnames),

            joinedload(Vulnerability.service)
            .joinedload(Service.host)
            .joinedload(Host.hostnames),

            joinedload(VulnerabilityWeb.service)
            .joinedload(Service.host)
            .joinedload(Host.hostnames),

            joinedload(VulnerabilityGeneric.evidence),
            joinedload(VulnerabilityGeneric.tags),
        ]
        return query.options(selectin_polymorphic(
            VulnerabilityGeneric,
            [Vulnerability, VulnerabilityWeb]
        ), *joinedloads)

    @property
    def model_class(self):
        if request.method == 'POST':
            return self.model_class_dict[request.json['type']]
        # We use Generic to list all vulns from all types
        return self.model_class_dict['VulnerabilityGeneric']

    def _get_schema_class(self):
        assert self.schema_class_dict is not None, "You must define schema_class"
        if request.method == 'POST':
            requested_type = request.json.get('type', None)
            if not requested_type:
                raise ValidationError('Type is required.')
            if requested_type not in self.schema_class_dict:
                raise InvalidUsage('Invalid vulnerability type.')
            return self.schema_class_dict[requested_type]
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
            'count': (pagination_metadata.total
                      if pagination_metadata is not None else len(vulns))
        }

    def count(self, **kwargs):
        """Override to change severity values"""
        res = super(VulnerabilityView, self).count(**kwargs)

        def convert_group(group):
            group = group.copy()
            severity_map = {
                "informational": "info",
                "medium": "med"
            }
            severity = group['severity']
            group['severity'] = group['name'] = severity_map.get(
                severity, severity)
            return group

        if request.args.get('group_by') == 'severity':
            res['groups'] = [convert_group(group) for group in res['groups']]
        return res


VulnerabilityView.register(vulns_api)
