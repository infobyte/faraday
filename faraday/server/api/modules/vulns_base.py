"""
Faraday Penetration Test IDE
Copyright (C) 2024  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
from base64 import b64encode, b64decode
from datetime import datetime
from http.client import (
    BAD_REQUEST as HTTP_BAD_REQUEST,
    FORBIDDEN as HTTP_FORBIDDEN,
    NOT_FOUND as HTTP_NOT_FOUND,
    OK as HTTP_OK,
)
from imghdr import what
from io import BytesIO
from json import dumps as json_dumps, loads as json_loads
from json.decoder import JSONDecodeError
from logging import getLogger
from pathlib import Path

# Related third party imports
from depot.manager import DepotManager
from filteralchemy import Filter, FilterSet, operators
from flask import Blueprint, abort, jsonify, make_response, request, send_file
from flask_classful import route
from flask_login import current_user
from marshmallow import Schema, ValidationError, fields, post_load
from marshmallow.validate import OneOf
from sqlalchemy import desc, func, insert as sqlalchemy_insert
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import (
    aliased,
    joinedload,
    noload,
    selectin_polymorphic,
    selectinload,
    undefer,
)
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.datastructures import ImmutableMultiDict
from wtforms import ValidationError as WTFormsValidationError

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    BulkDeleteMixin,
    BulkUpdateMixin,
    ContextMixin,
    CountMultiWorkspacedMixin,
    FilterAlchemyMixin,
    FilterSetMeta,
    InvalidUsage,
    PaginatedMixin,
    ReadOnlyView,
    get_filtered_data,
    get_workspace,
)
from faraday.server.api.modules.services_base import ServiceSchema
from faraday.server.config import faraday_server
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.fields import FaradayUploadedFile
from faraday.server.models import (
    Command,
    CommandObject,
    CustomFieldsSchema,
    File,
    Host,
    Hostname,
    Service,
    User,
    Vulnerability,
    VulnerabilityABC,
    VulnerabilityGeneric,
    VulnerabilityWeb,
    Workspace,
    db,
)
from faraday.server.schemas import (
    FaradayCustomField,
    MetadataSchema,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
    SeverityField,
)
from faraday.server.utils.csrf import validate_file
from faraday.server.utils.cwe import create_cwe
from faraday.server.utils.database import get_or_create
from faraday.server.utils.export import export_vulns_to_csv
from faraday.server.utils.filters import FlaskRestlessSchema
from faraday.server.utils.reference import create_reference
from faraday.server.utils.search import search
from faraday.server.utils.vulns import (
    FILTER_SET_FIELDS,
    FILTER_SET_STRICT_FIELDS,
    SCHEMA_FIELDS,
    WEB_SCHEMA_FIELDS,
    bulk_update_custom_attributes,
)
from faraday.settings import get_settings

vulns_api = Blueprint('vulns_api', __name__)
logger = getLogger(__name__)


class EvidenceSchema(AutoSchema):
    content_type = fields.Method('get_content_type')
    data = fields.Method('get_data')
    description = fields.String()

    class Meta:
        model = File
        fields = ('content_type', 'data', 'description')

    @staticmethod
    def get_content_type(file_obj):
        depot = DepotManager.get()
        return depot.get(file_obj.content.get('file_id')).content_type

    @staticmethod
    def get_data(file_obj):
        depot = DepotManager.get()
        return b64encode(depot.get(file_obj.content.get('file_id')).read()).decode()


class ImpactSchema(Schema):
    accountability = fields.Boolean(attribute='impact_accountability', default=False)
    availability = fields.Boolean(attribute='impact_availability', default=False)
    confidentiality = fields.Boolean(attribute='impact_confidentiality', default=False)
    integrity = fields.Boolean(attribute='impact_integrity', default=False)


class PatchAttachmentSchema(Schema):
    description = fields.String(required=True)


class CustomMetadataSchema(MetadataSchema):
    """
    Implements command_id and creator logic
    """
    command_id = fields.Integer(dump_only=True, attribute='creator_command_id')
    creator = fields.Method('get_creator', dump_only=True)

    @staticmethod
    def get_creator(obj):
        if obj.tool:
            return obj.tool
        else:
            return obj.creator_command_tool or 'Web UI'


class CVESchema(AutoSchema):
    name = fields.String()


class CVSS2Schema(AutoSchema):
    vector_string = fields.String(attribute="cvss2_vector_string", required=False, allow_none=True)
    base_score = fields.Float(attribute="cvss2_base_score", required=False, dump_only=True)
    exploitability_score = fields.Float(attribute="cvss2_exploitability_score", required=False, dump_only=True)
    impact_score = fields.Float(attribute="cvss2_impact_score", required=False, dump_only=True)
    base_severity = fields.String(attribute="cvss2_base_severity", dump_only=True, required=False)
    temporal_score = fields.Float(attribute="cvss2_temporal_score", required=False, dump_only=True)
    temporal_severity = fields.String(attribute="cvss2_temporal_severity", dump_only=True, required=False)
    environmental_score = fields.Float(attribute="cvss2_environmental_score", required=False, dump_only=True)
    environmental_severity = fields.String(attribute="cvss2_environmental_severity", dump_only=True, required=False)
    access_vector = fields.String(attribute="cvss2_access_vector", dump_only=True, required=False)
    access_complexity = fields.String(attribute="cvss2_access_complexity", dump_only=True, required=False)
    authentication = fields.String(attribute="cvss2_authentication", dump_only=True, required=False)
    confidentiality_impact = fields.String(attribute="cvss2_confidentiality_impact", dump_only=True, required=False)
    integrity_impact = fields.String(attribute="cvss2_integrity_impact", dump_only=True, required=False)
    availability_impact = fields.String(attribute="cvss2_availability_impact", dump_only=True, required=False)
    exploitability = fields.String(attribute="cvss2_exploitability", dump_only=True, required=False)
    remediation_level = fields.String(attribute="cvss2_remediation_level", dump_only=True, required=False)
    report_confidence = fields.String(attribute="cvss2_report_confidence", dump_only=True, required=False)
    collateral_damage_potential = fields.String(attribute="cvss2_collateral_damage_potential", dump_only=True, required=False)
    target_distribution = fields.String(attribute="cvss2_target_distribution", dump_only=True, required=False)
    confidentiality_requirement = fields.String(attribute="cvss2_confidentiality_requirement", dump_only=True, required=False)
    integrity_requirement = fields.String(attribute="cvss2_integrity_requirement", dump_only=True, required=False)
    availability_requirement = fields.String(attribute="cvss2_availability_requirement", dump_only=True, required=False)


class CVSS3Schema(AutoSchema):
    vector_string = fields.String(attribute="cvss3_vector_string", required=False, allow_none=True)
    base_score = fields.Float(attribute="cvss3_base_score", required=False, dump_only=True)
    exploitability_score = fields.Float(attribute="cvss3_exploitability_score", required=False, dump_only=True)
    impact_score = fields.Float(attribute="cvss3_impact_score", required=False, dump_only=True)
    base_severity = fields.String(attribute="cvss3_base_severity", dump_only=True, required=False)
    temporal_score = fields.Float(attribute="cvss3_temporal_score", required=False, dump_only=True)
    temporal_severity = fields.String(attribute="cvss3_temporal_severity", dump_only=True, required=False)
    environmental_score = fields.Float(attribute="cvss3_environmental_score", required=False, dump_only=True)
    environmental_severity = fields.String(attribute="cvss3_environmental_severity", dump_only=True, required=False)
    attack_vector = fields.String(attribute="cvss3_attack_vector", dump_only=True, required=False)
    attack_complexity = fields.String(attribute="cvss3_attack_complexity", dump_only=True, required=False)
    privileges_required = fields.String(attribute="cvss3_privileges_required", dump_only=True, required=False)
    user_interaction = fields.String(attribute="cvss3_user_interaction", dump_only=True, required=False)
    confidentiality_impact = fields.String(attribute="cvss3_confidentiality_impact", dump_only=True, required=False)
    integrity_impact = fields.String(attribute="cvss3_integrity_impact", dump_only=True, required=False)
    availability_impact = fields.String(attribute="cvss3_availability_impact", dump_only=True, required=False)
    exploit_code_maturity = fields.String(attribute="cvss3_exploit_code_maturity", dump_only=True, required=False)
    remediation_level = fields.String(attribute="cvss3_remediation_level", dump_only=True, required=False)
    report_confidence = fields.String(attribute="cvss3_report_confidence", dump_only=True, required=False)
    confidentiality_requirement = fields.String(attribute="cvss3_confidentiality_requirement", dump_only=True, required=False)
    integrity_requirement = fields.String(attribute="cvss3_integrity_requirement", dump_only=True, required=False)
    availability_requirement = fields.String(attribute="cvss3_availability_requirement", dump_only=True, required=False)
    modified_attack_vector = fields.String(attribute="cvss3_modified_attack_vector", dump_only=True, required=False)
    modified_attack_complexity = fields.String(attribute="cvss3_modified_attack_complexity", dump_only=True, required=False)
    modified_privileges_required = fields.String(attribute="cvss3_modified_privileges_required", dump_only=True, required=False)
    modified_user_interaction = fields.String(attribute="cvss3_modified_user_interaction", dump_only=True, required=False)
    modified_scope = fields.String(attribute="cvss3_modified_scope", dump_only=True, required=False)
    modified_confidentiality_impact = fields.String(attribute="cvss3_modified_confidentiality_impact", dump_only=True, required=False)
    modified_integrity_impact = fields.String(attribute="cvss3_modified_integrity_impact", dump_only=True, required=False)
    modified_availability_impact = fields.String(attribute="cvss3_modified_availability_impact", dump_only=True, required=False)
    scope = fields.String(attribute="cvss3_scope", dump_only=True, required=False)


class CVSS4Schema(AutoSchema):
    vector_string = fields.String(attribute="cvss4_vector_string", required=False, allow_none=True)
    base_score = fields.Float(attribute="cvss4_base_score", required=False, dump_only=True)
    base_severity = fields.String(attribute="cvss4_base_severity", dump_only=True, required=False)
    attack_vector = fields.String(attribute="cvss4_attack_vector", dump_only=True, required=False)
    attack_complexity = fields.String(attribute="cvss4_attack_complexity", dump_only=True, required=False)
    attack_requirements = fields.String(attribute="cvss4_attack_requirements", dump_only=True, required=False)
    privileges_required = fields.String(attribute="cvss4_privileges_required", dump_only=True, required=False)
    user_interaction = fields.String(attribute="cvss4_user_interaction", dump_only=True, required=False)
    vulnerable_system_confidentiality_impact = fields.String(attribute="cvss4_vulnerable_system_confidentiality_impact", dump_only=True, required=False)
    subsequent_system_confidentiality_impact = fields.String(attribute="cvss4_subsequent_system_confidentiality_impact", dump_only=True, required=False)
    vulnerable_system_integrity_impact = fields.String(attribute="cvss4_vulnerable_system_integrity_impact", dump_only=True, required=False)
    subsequent_system_integrity_impact = fields.String(attribute="cvss4_subsequent_system_integrity_impact", dump_only=True, required=False)
    vulnerable_system_availability_impact = fields.String(attribute="cvss4_vulnerable_system_availability_impact", dump_only=True, required=False)
    subsequent_system_availability_impact = fields.String(attribute="cvss4_subsequent_system_availability_impact", dump_only=True, required=False)
    safety = fields.String(attribute="cvss4_safety", dump_only=True, required=False)
    automatable = fields.String(attribute="cvss4_automatable", dump_only=True, required=False)
    recovery = fields.String(attribute="cvss4_recovery", dump_only=True, required=False)
    value_density = fields.String(attribute="cvss4_value_density", dump_only=True, required=False)
    vulnerability_response_effort = fields.String(attribute="cvss4_vulnerability_response_effort", dump_only=True, required=False)
    provider_urgency = fields.String(attribute="cvss4_provider_urgency", dump_only=True, required=False)
    modified_attack_vector = fields.String(attribute="cvss4_modified_attack_vector", dump_only=True, required=False)
    modified_attack_complexity = fields.String(attribute="cvss4_modified_attack_complexity", dump_only=True, required=False)
    modified_attack_requirements = fields.String(attribute="cvss4_modified_attack_requirements", dump_only=True, required=False)
    modified_privileges_required = fields.String(attribute="cvss4_modified_privileges_required", dump_only=True, required=False)
    modified_user_interaction = fields.String(attribute="cvss4_modified_user_interaction", dump_only=True, required=False)
    modified_vulnerable_system_confidentiality_impact = fields.String(attribute="cvss4_modified_vulnerable_system_confidentiality_impact", dump_only=True, required=False)
    modified_subsequent_system_confidentiality_impact = fields.String(attribute="cvss4_modified_subsequent_system_confidentiality_impact", dump_only=True, required=False)
    modified_vulnerable_system_integrity_impact = fields.String(attribute="cvss4_modified_vulnerable_system_integrity_impact", dump_only=True, required=False)
    modified_subsequent_system_integrity_impact = fields.String(attribute="cvss4_modified_subsequent_system_integrity_impact", dump_only=True, required=False)
    modified_vulnerable_system_availability_impact = fields.String(attribute="cvss4_modified_vulnerable_system_availability_impact", dump_only=True, required=False)
    modified_subsequent_system_availability_impact = fields.String(attribute="cvss4_modified_subsequent_system_availability_impact", dump_only=True, required=False)
    confidentiality_requirement = fields.String(attribute="cvss4_confidentiality_requirement", dump_only=True, required=False)
    integrity_requirement = fields.String(attribute="cvss4_integrity_requirement", dump_only=True, required=False)
    availability_requirement = fields.String(attribute="cvss4_availability_requirement", dump_only=True, required=False)
    exploit_maturity = fields.String(attribute="cvss4_exploit_maturity", dump_only=True, required=False)


class RiskSchema(AutoSchema):
    score = fields.Int(attribute='risk', dump_only=True)
    severity = fields.Method(serialize='get_risk_severity', dump_only=True)

    @staticmethod
    def get_risk_severity(obj):
        if not obj.risk:
            return None
        if 0 <= obj.risk < 40:
            return 'low'
        if 40 <= obj.risk < 70:
            return 'medium'
        if 70 <= obj.risk < 90:
            return 'high'
        if 90 <= obj.risk <= 100:
            return 'critical'


class CWESchema(AutoSchema):
    name = fields.String()


class OWASPSchema(AutoSchema):
    name = fields.String()


class ReferenceSchema(AutoSchema):
    name = fields.String()
    type = fields.String()


class VulnerabilitySchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    _rev = fields.String(dump_only=True, default='')
    _attachments = fields.Method(serialize='get_attachments', deserialize='load_attachments', default=[])
    owned = fields.Boolean(dump_only=True, default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    impact = SelfNestedField(ImpactSchema())
    desc = fields.String(attribute='description')
    description = fields.String(dump_only=True)
    policyviolations = fields.List(fields.String, attribute='policy_violations')
    refs = fields.List(fields.Nested(ReferenceSchema), attribute='refs')
    issuetracker = fields.Method(serialize='get_issuetracker_json', deserialize='load_issuetracker', dump_only=True)
    cve = fields.List(fields.String(), attribute='cve')
    cvss2 = SelfNestedField(CVSS2Schema())
    cvss3 = SelfNestedField(CVSS3Schema())
    cvss4 = SelfNestedField(CVSS4Schema())
    tool = fields.String(attribute='tool')
    parent = fields.Method(serialize='get_parent', deserialize='load_parent', required=True)
    parent_type = MutableField(fields.Method('get_parent_type'), fields.String(), required=True)
    cwe = fields.List(fields.Pluck(CWESchema(), "name"))
    tags = PrimaryKeyRelatedField('name', dump_only=True, many=True)
    easeofresolution = fields.String(
        attribute='ease_of_resolution',
        validate=OneOf(Vulnerability.EASE_OF_RESOLUTIONS),
        allow_none=True,
    )
    hostnames = PrimaryKeyRelatedField('name', many=True, dump_only=True)
    service = fields.Nested(ServiceSchema(only=[
        '_id', 'ports', 'status', 'protocol', 'name', 'version', 'summary'
    ]), dump_only=True)
    host = fields.Integer(dump_only=True, attribute='host_id')
    severity = SeverityField(required=True)
    status = fields.Method(
        serialize='get_status',
        validate=OneOf(Vulnerability.STATUSES + ['opened']),
        deserialize='load_status',
    )
    type = fields.Method(serialize='get_type', deserialize='load_type', required=True)
    obj_id = fields.String(dump_only=True, attribute='id')
    target = fields.String(dump_only=True, attribute='target_host_ip')
    host_os = fields.String(dump_only=True, attribute='target_host_os')
    metadata = SelfNestedField(CustomMetadataSchema())
    date = fields.DateTime(attribute='create_date', dump_only=True)  # This is only used for sorting
    custom_fields = FaradayCustomField(table_name='vulnerability', attribute='custom_fields')
    external_id = fields.String(allow_none=True)
    command_id = fields.Int(required=False, load_only=True)
    risk = SelfNestedField(RiskSchema(), dump_only=True)
    workspace_name = fields.String(attribute='workspace.name', dump_only=True)

    class Meta:
        model = Vulnerability
        fields = SCHEMA_FIELDS

    @staticmethod
    def get_type(obj):
        return obj.__class__.__name__

    @staticmethod
    def get_attachments(obj):
        res = {}

        for file_obj in obj.evidence:
            try:
                res[file_obj.filename] = EvidenceSchema().dump(file_obj)
            except OSError:
                logger.warning("File not found. Did you move your server?")

        return res

    @staticmethod
    def load_attachments(value):
        return value

    @staticmethod
    def get_parent(obj):
        return obj.service_id or obj.host_id

    @staticmethod
    def get_parent_type(obj):
        assert obj.service_id is not None or obj.host_id is not None
        return 'Service' if obj.service_id is not None else 'Host'

    @staticmethod
    def get_status(obj):
        return obj.status

    @staticmethod
    def get_issuetracker_json(obj):
        return {}

    @staticmethod
    def load_issuetracker(obj):
        return {}

    @staticmethod
    def load_status(value):
        if value == 'opened':
            return 'open'
        return value

    @staticmethod
    def load_type(value):
        if value == 'Vulnerability':
            return 'vulnerability'
        if value == 'VulnerabilityWeb':
            return 'vulnerability_web'
        else:
            raise ValidationError('Invalid vulnerability type.')

    @staticmethod
    def load_parent(value):
        try:
            # sometimes api requests send str or unicode.
            value = int(value)
        except ValueError as e:
            raise ValidationError("Invalid parent type") from e
        return value

    # @post_load
    # def post_load_owasp(self, data, **kwargs):
    #     owasp = data.pop('owasp', None)
    #     if owasp:
    #         data['owasp'] = [item['name'] for item in owasp]
    #     return data

    @post_load
    def post_load_impact(self, data, **kwargs):
        # Unflatten impact (move data[impact][*] to data[*])
        impact = data.pop('impact', None)
        if impact:
            data.update(impact)
        return data

    @post_load
    def post_load_parent(self, data, **kwargs):
        # schema guarantees that parent_type exists.
        parent_class = None
        parent_field = None
        parent_type = data.pop('parent_type', None)
        parent_id = data.pop('parent', None)

        if not parent_type and not parent_id:
            return data
        if parent_id and parent_type is None:
            raise ValidationError('Trying to modify parent with no parent_type')
        if parent_type and parent_id is None:
            raise ValidationError('Trying to modify parent_type but parent not sent')

        if parent_type == 'Host':
            parent_class = Host
            parent_field = 'host_id'
            data['service_id'] = None
        if parent_type == 'Service':
            parent_class = Service
            parent_field = 'service_id'
            data['host_id'] = None
        if not parent_class:
            raise ValidationError('Unknown parent type')
        if parent_type == 'Host':
            if 'type' in data:
                if data['type'] == 'vulnerability_web':
                    raise ValidationError('Trying to set a host for a vulnerability web')
            elif kwargs.get("partial", False):
                vulnerability = self.context.get("object", None)
                if vulnerability:
                    if vulnerability.type == 'vulnerability_web':
                        raise ValidationError('Trying to set a host for a vulnerability web')
        try:
            parent = db.session.query(parent_class).join(Workspace).filter(
                Workspace.name == self.context['workspace_name'],
                parent_class.id == parent_id
            ).one()
        except NoResultFound as e:
            raise ValidationError(f'Parent id not found: {parent_id}') from e
        data[parent_field] = parent.id
        # TODO migration: check what happens when updating the parent from
        # service to host or vice versa
        return data

    @post_load
    def post_load_cvss2(self, data, **kwargs):
        return self._get_vector_string(data, 'cvss2')

    @post_load
    def post_load_cvss3(self, data, **kwargs):
        return self._get_vector_string(data, 'cvss3')

    @post_load
    def post_load_cvss4(self, data, **kwargs):
        return self._get_vector_string(data, 'cvss4')

    @staticmethod
    def _get_vector_string(data, version):
        if version not in ['cvss2', 'cvss3', 'cvss4']:
            return data

        if version in data:
            vector_string = f'{version}_vector_string'
            cvss = data.pop(version)
            if vector_string in cvss:
                data[vector_string] = cvss[vector_string]
        return data


class VulnerabilityWebSchema(VulnerabilitySchema):
    method = fields.String(default='')
    params = fields.String(attribute='parameters', default='')
    pname = fields.String(attribute='parameter_name', default='')
    path = fields.String(default='')
    response = fields.String(default='')
    request = fields.String(default='')
    website = fields.String(default='')
    query = fields.String(attribute='query_string', default='')
    status_code = fields.Integer(allow_none=True)

    class Meta:
        model = VulnerabilityWeb
        fields = WEB_SCHEMA_FIELDS


# Use this override for filterset fields that filter by en exact match by
# default, and not by a similar one (like operator)
_strict_filtering = {'default_operator': operators.Equal}


class IDFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.id == value)


class StatusCodeFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.status_code == value)


class TargetFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.target_host_ip == value)


class TypeFilter(Filter):
    def filter(self, query, model, attr, value):
        type_map = {
            'Vulnerability': 'vulnerability',
            'VulnerabilityWeb': 'vulnerability_web',
        }
        assert value in type_map
        return query.filter(model.__table__.c.type == type_map[value])


class CreatorFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.creator_command_tool.ilike(
            '%' + value + '%'))


class ServiceFilter(Filter):
    def filter(self, query, model, attr, value):
        alias = aliased(Service, name='service_filter')
        return query.join(
            alias,
            alias.id == model.__table__.c.service_id).filter(
            alias.name == value
        )


class HostnamesFilter(Filter):
    def filter(self, query, model, attr, value):
        alias = aliased(Hostname, name='hostname_filter')

        value_list = value.split(",")

        service_hostnames_query = query.join(Service, Service.id == Vulnerability.service_id). \
            join(Host). \
            join(alias). \
            filter(alias.name.in_(value_list))

        host_hostnames_query = query.join(Host, Host.id == Vulnerability.host_id). \
            join(alias). \
            filter(alias.name.in_(value_list))

        query = service_hostnames_query.union(host_hostnames_query)
        return query


class CustomILike(operators.Operator):
    """A filter operator that puts a % in the beginning and in the
    end of the search string to force a partial search"""

    def __call__(self, query, model, attr, value):
        column = getattr(model, attr)
        condition = column.ilike('%' + value + '%')
        return query.filter(condition)


class VulnerabilityFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = VulnerabilityWeb  # It has all the fields
        fields = FILTER_SET_FIELDS
        strict_fields = FILTER_SET_STRICT_FIELDS
        default_operator = CustomILike
        column_overrides = {field: _strict_filtering for field in strict_fields}
        operators = (CustomILike, operators.Equal)

    id = IDFilter(fields.Int())
    target = TargetFilter(fields.Str())
    type = TypeFilter(fields.Str(validate=[OneOf(['Vulnerability', 'VulnerabilityWeb'])]))
    creator = CreatorFilter(fields.Str())
    service = ServiceFilter(fields.Str())
    severity = Filter(SeverityField())
    ease_of_resolution = Filter(fields.String(
        validate=OneOf(Vulnerability.EASE_OF_RESOLUTIONS),
        allow_none=True))
    status_code = StatusCodeFilter(fields.Int())
    status = Filter(fields.Function(
        deserialize=lambda val: 'open' if val == 'opened' else val,
        validate=OneOf(Vulnerability.STATUSES + ['opened'])
    ))
    hostnames = HostnamesFilter(fields.Str())
    confirmed = Filter(fields.Boolean())

    def filter(self):
        """Generate a filtered query from request parameters.

        :returns: Filtered SQLAlchemy query
        """
        # TODO migration: this can became a normal filter instead of a custom
        # one, since now we can use creator_command_id
        command_id = request.args.get('command_id')

        # The web UI uses old field names. Translate them into the new field
        # names to maintain backwards compatibility
        param_mapping = {
            'query': 'query_string',
            'pname': 'parameter_name',
            'params': 'parameters',
            'easeofresolution': 'ease_of_resolution',
        }
        new_args = request.args.copy()
        for (old_param, real_param) in param_mapping.items():
            try:
                new_args[real_param] = request.args[old_param]
            except KeyError:
                pass
        request.args = ImmutableMultiDict(new_args)

        query = super().filter()

        if command_id:
            # query = query.filter(CommandObject.command_id == int(command_id))
            query = query.filter(VulnerabilityGeneric.creator_command_id
                                 == int(command_id))  # TODO migration: handle invalid int()
        return query


class VulnerabilityView(
    PaginatedMixin,
    FilterAlchemyMixin,
    ReadOnlyView,
    CountMultiWorkspacedMixin,
    ContextMixin,
    BulkDeleteMixin,
    BulkUpdateMixin,
):
    route_base = 'vulns'
    filterset_class = VulnerabilityFilterSet
    sort_model_class = VulnerabilityWeb  # It has all the fields
    sort_pass_silently = True  # For compatibility with the Web UI
    order_field = desc(VulnerabilityGeneric.confirmed), VulnerabilityGeneric.severity, VulnerabilityGeneric.create_date
    get_joinedloads = [Vulnerability.evidence, Vulnerability.creator]

    model_class_dict = {
        'Vulnerability': Vulnerability,
        'VulnerabilityWeb': VulnerabilityWeb,
        'VulnerabilityGeneric': VulnerabilityGeneric,  # For listing objects
    }
    schema_class_dict = {
        'Vulnerability': VulnerabilitySchema,
        'VulnerabilityWeb': VulnerabilityWebSchema
    }

    def _get_schema_instance(self, route_kwargs, **kwargs):
        schema = super()._get_schema_instance(route_kwargs, **kwargs)

        return schema

    @staticmethod
    def _process_attachments(obj, attachments):
        old_attachments = db.session.query(File).options(
            joinedload(File.creator),
            joinedload(File.update_user)
        ).filter_by(
            object_id=obj.id,
            object_type='vulnerability',
        )

        for old_attachment in old_attachments:
            db.session.delete(old_attachment)

        for filename, attachment in attachments.items():
            if 'image' in attachment['content_type']:
                image_format = what(None, h=b64decode(attachment['data']))
                if image_format and image_format.lower() == "webp":
                    logger.info("Evidence can not be webp format")
                    abort(HTTP_BAD_REQUEST, "Evidence can not be webp format")

            faraday_file = FaradayUploadedFile(b64decode(attachment['data']))
            filename = filename.replace(" ", "_")
            description = attachment.get('description')
            get_or_create(
                db.session,
                File,
                object_id=obj.id,
                object_type='vulnerability',
                name=Path(filename).stem,
                filename=Path(filename).name,
                content=faraday_file,
                description=description,
            )

    def _perform_bulk_update(self, ids, data, **kwargs):
        returning_rows = [
            VulnerabilityGeneric.id,
            VulnerabilityGeneric.name,
            VulnerabilityGeneric.severity,
            VulnerabilityGeneric.risk,
            VulnerabilityGeneric.host_id,
            Vulnerability.service_id,
        ]
        kwargs['returning'] = returning_rows

        workspace_name = kwargs.get('workspace_name')
        if workspace_name:
            debounce_workspace_update(workspace_name)

        if (len(data) > 0 and len(ids) > 0) and 'custom_fields' in data.keys():
            return bulk_update_custom_attributes(ids, data)
        return super()._perform_bulk_update(ids, data, **kwargs)

    def _get_eagerloaded_query(self, *args, **kwargs):
        """
        Eager hostnames loading.
        This is too complex to get_joinedloads, so I have to override the function.
        """
        query = super()._get_eagerloaded_query(*args, **kwargs)
        options = [
            joinedload(Vulnerability.host).
            load_only(Host.id).  # Only hostnames are needed
            joinedload(Host.hostnames),

            joinedload(Vulnerability.service).
            joinedload(Service.host).
            joinedload(Host.hostnames),

            joinedload(VulnerabilityWeb.service).
            joinedload(Service.host).
            joinedload(Host.hostnames),

            joinedload(VulnerabilityGeneric.update_user),
            undefer(VulnerabilityGeneric.creator_command_id),
            undefer(VulnerabilityGeneric.creator_command_tool),
            undefer(VulnerabilityGeneric.target_host_ip),
            undefer(VulnerabilityGeneric.target_host_os),
            joinedload(VulnerabilityGeneric.tags),
            joinedload(VulnerabilityGeneric.cwe),
            joinedload(VulnerabilityGeneric.owasp),
            joinedload(Vulnerability.owasp),
            joinedload(VulnerabilityWeb.owasp),
        ]

        if request.args.get('get_evidence'):
            options.append(joinedload(VulnerabilityGeneric.evidence))
        else:
            options.append(noload(VulnerabilityGeneric.evidence))

        return query.options(selectin_polymorphic(
            VulnerabilityGeneric,
            [Vulnerability, VulnerabilityWeb]
        ), *options)

    def _filter_query(self, query):
        query = super()._filter_query(query)
        search_term = request.args.get('search', None)
        if search_term is not None:
            # TODO migration: add more fields to free text search
            like_term = '%' + search_term + '%'
            match_name = VulnerabilityGeneric.name.ilike(like_term)
            match_desc = VulnerabilityGeneric.description.ilike(like_term)
            query = query.filter(match_name | match_desc)
        return query

    @property
    def model_class(self):
        if request.method == 'POST' and request.json:
            return self.model_class_dict[request.json.get('type', 'VulnerabilityGeneric')]
        # We use Generic to list all vulns from all types
        return self.model_class_dict['VulnerabilityGeneric']

    def _get_schema_class(self):
        assert self.schema_class_dict is not None, "You must define schema_class"
        if request.method == 'POST' and request.json:
            requested_type = request.json.get('type')
            if not requested_type:
                raise InvalidUsage('Type is required.')
            if requested_type not in self.schema_class_dict:
                raise InvalidUsage('Invalid vulnerability type.')
            return self.schema_class_dict[requested_type]
        # We use web since it has all the fields
        return self.schema_class_dict['VulnerabilityWeb']

    def _envelope_list(self, objects, pagination_metadata=None):
        vulns = []
        for index, vuln in enumerate(objects):
            # we use index when the filter endpoint uses group by and
            # the _id was not used in the group by
            vulns.append({
                'id': vuln.get('_id', index),
                'key': vuln.get('_id', index),
                'value': vuln
            })
        return {
            'vulnerabilities': vulns,
            'count': (pagination_metadata.total
                      if pagination_metadata is not None else len(vulns))
        }

    def count(self, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability"]
          summary: "Group vulnerabilities by the field set in the group_by GET parameter."
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: VulnerabilityWeb
            404:
              description: group_by is not specified
        tags: ["Vulnerability"]
        responses:
          200:
            description: Ok
        """
        res = super().count(**kwargs)

        def convert_group(group, type):
            group = group.copy()

            if type == "severity":
                severity_map = {
                    "informational": "info",
                    "medium": "med"
                }
                severity = group[type]
                group['severity'] = group['name'] = severity_map.get(severity, severity)
            elif type == "confirmed":
                confirmed_map = {
                    1: "True",
                    0: "False"
                }
                confirmed = group[type]
                group[type] = group['name'] = confirmed_map.get(confirmed, confirmed)
            else:
                group['name'] = group[type]
            return group

        if request.args.get('group_by') == 'severity':
            res['groups'] = [convert_group(group, 'severity') for group in res['groups']]
        if request.args.get('group_by') == 'confirmed':
            res['groups'] = [convert_group(group, 'confirmed') for group in res['groups']]
        return res

    @route('/<int:vuln_id>/attachment', methods=['POST'])
    def post_attachment(self, vuln_id, **kwargs):
        """
        ---
        post:
          tags: ["Vulnerability", "File"]
          description: Creates a new attachment in the vuln
          responses:
            201:
              description: Created
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id),
            operation="write"
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        try:
            validate_file(request)
        except FileNotFoundError:
            abort(HTTP_BAD_REQUEST, "File not found in request")
        except WTFormsValidationError as e:
            abort(HTTP_FORBIDDEN, str(e))

        vuln = VulnerabilitySchema().dump(vuln_permission_check)
        filename = request.files['file'].filename
        _attachments = vuln['_attachments']

        if filename in _attachments:
            message = 'Evidence already exists in vuln'
            return make_response(jsonify(message=message, success=False, code=HTTP_BAD_REQUEST), HTTP_BAD_REQUEST)

        description = request.form.get('description')

        faraday_file = FaradayUploadedFile(request.files['file'].read())
        get_or_create(
            db.session,
            File,
            object_id=vuln_id,
            object_type='vulnerability',
            name=filename,
            filename=filename,
            content=faraday_file,
            description=description,
        )
        db.session.commit()
        debounce_workspace_update(vuln_permission_check.workspace.name)
        message = 'Evidence upload was successful'
        logger.info(message)
        return jsonify({'message': message})

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['PATCH'])
    def patch_attachment(self, vuln_id, attachment_filename, **kwargs):
        """
        ---
        patch:
          tags: ["Vulnerability", "File"]
          description: Updates the description of an attachment.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    description:
                      type: string
                      example: "Updated attachment description"
          responses:
            200:
              description: Updated successfully
            404:
              description: Attachment or Vulnerability not found
            400:
              description: Validation error
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id),
            operation="write"
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        # Validate JSON input
        schema = PatchAttachmentSchema()
        try:
            data = schema.load(request.get_json())
        except ValidationError as e:
            abort(HTTP_BAD_REQUEST, str(e.messages))

        # Check if attachment exists
        try:
            attachment = db.session.query(File).filter_by(
                object_type='vulnerability',
                object_id=vuln_id,
                filename=attachment_filename
            ).one()
        except NoResultFound:
            abort(HTTP_NOT_FOUND, "Attachment or Vulnerability not found")

        # Update and commit the changes
        attachment.description = data["description"]
        db.session.commit()
        debounce_workspace_update(vuln_permission_check.workspace.name)

        return jsonify({"message": "Attachment updated successfully"}), HTTP_OK

    @route('/filter')
    def filter(self, **kwargs):
        """
        ---
        get:
          tags: ["Filter", "Vulnerability"]
          description: Filters, sorts and groups vulnerabilities using a json with parameters. These parameters must be part of the model.
          parameters:
          - in: query
            name: q
            description: Recursive json with filters that supports operators. The json could also contain sort and group.
          responses:
            200:
              description: Returns filtered, sorted and grouped results
              content:
                application/json:
                  schema: FlaskRestlessSchema
            400:
              description: Invalid q was sent to the server
        tags: ["Filter", "Vulnerability"]
        responses:
          200:
            description: Ok
        """
        workspace_name = kwargs.get('workspace_name')
        filters = request.args.get('q', '{}')
        export_csv = request.args.get('export_csv', '')
        filtered_vulns, count = self._filter(
            filters, exclude_list=('_attachments', 'desc') if export_csv.lower() == 'true' else None, **kwargs
        )

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        if export_csv.lower() == 'true':
            custom_fields_columns = []
            for custom_field in db.session.query(CustomFieldsSchema).order_by(CustomFieldsSchema.field_order):
                custom_fields_columns.append(custom_field.field_name)
            memory_file = export_vulns_to_csv(filtered_vulns, custom_fields_columns)
            if workspace_name:
                return send_file(memory_file,
                                 attachment_filename=f"Faraday-SR-{workspace_name}.csv",
                                 as_attachment=True,
                                 cache_timeout=-1)
            else:
                return send_file(memory_file,
                                 attachment_filename="Faraday-SR-Context.csv",
                                 as_attachment=True,
                                 cache_timeout=-1)
        else:
            return self._envelope_list(filtered_vulns, pagination_metadata)

    def _hostname_filters(self, filters):
        res_filters = []
        hostname_filters = []
        for search_filter in filters:
            if 'or' not in search_filter and 'and' not in search_filter:
                fieldname = search_filter.get('name')
                operator = search_filter.get('op')
                argument = search_filter.get('val')
                otherfield = search_filter.get('field')
                field_filter = {
                    "name": fieldname,
                    "op": operator,
                    "val": argument
                }
                if otherfield:
                    field_filter.update({"field": otherfield})
                if fieldname == 'hostnames':
                    hostname_filters.append(field_filter)
                else:
                    res_filters.append(field_filter)
            elif 'or' in search_filter:
                or_filters, deep_hostname_filters = self._hostname_filters(search_filter['or'])
                if or_filters:
                    res_filters.append({"or": or_filters})
                hostname_filters += deep_hostname_filters
            elif 'and' in search_filter:
                and_filters, deep_hostname_filters = self._hostname_filters(search_filter['and'])
                if and_filters:
                    res_filters.append({"and": and_filters})
                hostname_filters += deep_hostname_filters

        return res_filters, hostname_filters

    def _generate_filter_query(
            self,
            vulnerability_class,
            filters,
            hostname_filters,
            marshmallow_params,
            is_csv=False,
            **kwargs,
    ):
        workspace = kwargs.get('workspace')

        hosts_os_filter = [host_os_filter for host_os_filter in filters.get('filters', []) if
                           host_os_filter.get('name') == 'host__os']

        if hosts_os_filter:
            # remove host__os filters from filters due to a bug
            hosts_os_filter = hosts_os_filter[0]
            filters['filters'] = [host_os_filter for host_os_filter in filters.get('filters', []) if
                                  host_os_filter.get('name') != 'host__os']

        vulns = search(db.session, vulnerability_class, filters)

        if workspace:
            vulns = vulns.filter(VulnerabilityGeneric.workspace == workspace)
        else:
            vulns = self._apply_filter_context(vulns)
            vulns = vulns.filter(vulnerability_class.workspace.has(active=True))

        if hosts_os_filter:
            os_value = hosts_os_filter['val']
            vulns = vulns.join(Host).join(Service).filter(Host.os == os_value)

        if 'group_by' not in filters:
            options = [
                joinedload('cve_instances'),
                joinedload('owasp'),
                joinedload('cwe'),
                joinedload(VulnerabilityGeneric.tags),
                joinedload('host'),
                joinedload('service'),
                joinedload('creator'),
                joinedload('update_user'),
                undefer('target'),
                undefer('target_host_os'),
                undefer('target_host_ip'),
                undefer('creator_command_tool'),
                undefer('creator_command_id'),
                noload('evidence')
            ]
            if is_csv:
                options = options + [
                    joinedload('policy_violation_instances'),
                    selectinload('refs')
                ]

            vulns = vulns.options(selectin_polymorphic(
                VulnerabilityGeneric,
                [Vulnerability, VulnerabilityWeb]
            ), *options)
        return vulns

    def _filter(self, filters, exclude_list=None, **kwargs):
        hostname_filters = []
        vulns = None
        try:
            filters = FlaskRestlessSchema().load(json_loads(filters)) or {}
            if filters:
                filters['filters'], hostname_filters = self._hostname_filters(filters.get('filters', []))
        except (ValidationError, JSONDecodeError, AttributeError) as ex:
            logger.exception(ex)
            abort(HTTP_BAD_REQUEST, "Invalid filters")

        workspace_name = kwargs.get('workspace_name')
        if workspace_name:
            kwargs['workspace'] = get_workspace(workspace_name)

        marshmallow_params = {'many': True, 'context': {}, 'exclude': (
            '_attachments',
            'description',
            'desc',
            'refs',
            'request',
            'resolution',
            'response',
            'policyviolations',
            'data',
        ) if not exclude_list else exclude_list}
        if 'group_by' not in filters:
            offset = None
            if 'offset' in filters:
                offset = filters.pop('offset')

            limit = get_settings("query_limits").vuln_query_limit
            if 'limit' in filters:
                if limit:
                    filter_limit = filters.pop('limit')
                    if limit > filter_limit > 0:
                        limit = filter_limit
                else:
                    limit = filters.pop('limit')

            try:
                vulns = self._generate_filter_query(
                    VulnerabilityGeneric,
                    filters,
                    hostname_filters,
                    marshmallow_params,
                    bool(exclude_list),
                    **kwargs,
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            # In vulns count we do not need order
            total_vulns = vulns.order_by(None)
            if limit:
                vulns = vulns.limit(limit)
            if offset:
                vulns = vulns.offset(offset)

            vulns = self.schema_class_dict['VulnerabilityWeb'](**marshmallow_params).dump(vulns)
            return vulns, total_vulns.count()

        else:
            try:
                vulns = self._generate_filter_query(
                    VulnerabilityGeneric,
                    filters,
                    hostname_filters,
                    marshmallow_params,
                    **kwargs,
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            vulns_data, rows_count = get_filtered_data(filters, vulns)

            return vulns_data, rows_count

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['GET'])
    def get_attachment(self, vuln_id, attachment_filename, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability", "File"]
          description: Get a vuln attachment
          responses:
            200:
              description: Ok
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id)
        ).first()

        file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                                    object_id=vuln_id,
                                                    filename=attachment_filename.replace(" ", "%20")).first()

        if not vuln_permission_check or not file_obj:
            abort(HTTP_NOT_FOUND, "File not found")

        depot = DepotManager.get()
        depot_file = depot.get(file_obj.content.get('file_id'))

        if not depot_file:
            abort(HTTP_NOT_FOUND, "File not found")

        if depot_file.content_type.startswith('image/'):
            # Image content types are safe (they can't be executed like
            # html) so we don't have to force the download of the file
            as_attachment = False
        else:
            as_attachment = True

        return send_file(
            BytesIO(depot_file.read()),
            attachment_filename=depot_file.filename,
            as_attachment=as_attachment,
            mimetype=depot_file.content_type
        )

    @route('/<int:vuln_id>/attachment', methods=['GET'])
    def get_attachments_by_vuln(self, vuln_id, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability", "File"]
          description: Gets an attachment for a vulnerability
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: EvidenceSchema
            403:
              description: Workspace disabled or no permission
            404:
              description: Not Found
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id)
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        files = db.session.query(File).filter_by(object_type='vulnerability', object_id=vuln_id).all()

        res = {}
        for file_obj in files:
            ret = EvidenceSchema().dump(file_obj)
            res[file_obj.filename] = ret

        return jsonify(res)

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['DELETE'])
    def delete_attachment(self, vuln_id, attachment_filename, **kwargs):
        """
        ---
        delete:
          tags: ["Vulnerability", "File"]
          description: Remove a vuln attachment
          responses:
            200:
              description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id)
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                                    object_id=vuln_id,
                                                    filename=attachment_filename).first()
        if not file_obj:
            abort(HTTP_NOT_FOUND, "File not found")

        db.session.delete(file_obj)
        db.session.commit()
        depot = DepotManager.get()
        depot.delete(file_obj.content.get('file_id'))
        message = 'Attachment was successfully deleted'
        logger.info(message)
        return jsonify({'message': message})

    @route('export_csv', methods=['GET'])
    def export_csv(self, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability", "File"]
          description: Get a CSV file with all vulns from a workspace
          responses:
            200:
              description: Ok
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        workspace_name = kwargs.get('workspace_name')
        confirmed = bool(request.args.get('confirmed'))
        filters = request.args.get('q', '{}')
        custom_fields_columns = []

        for custom_field in db.session.query(CustomFieldsSchema).order_by(CustomFieldsSchema.field_order):
            custom_fields_columns.append(custom_field.field_name)

        if confirmed:
            if 'filters' not in filters:
                filters = {'filters': []}
            filters['filters'].append({
                "name": "confirmed",
                "op": "==",
                "val": "true"
            })
            filters = json_dumps(filters)

        vulns_query, _ = self._filter(filters, exclude_list=('_attachments', 'desc'), **kwargs)
        memory_file = export_vulns_to_csv(vulns_query, custom_fields_columns)

        if workspace_name:
            logger.info(f"CSV file with vulnerabilities from workspace {workspace_name} exported")
            return send_file(memory_file,
                             attachment_filename=f"Faraday-SR-{workspace_name}.csv",
                             as_attachment=True,
                             cache_timeout=-1)
        else:
            logger.info("CSV file exported with context vulnerabilities")
            return send_file(memory_file,
                             attachment_filename="Faraday-SR-Context.csv",
                             as_attachment=True,
                             cache_timeout=-1)

    @route('top_users', methods=['GET'])
    def top_users(self, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability"]
          params: limit
          description: Gets a list of top users having account its uploaded vulns
          responses:
            200:
              description: List of top users
        tags: ["Vulnerability"]
        responses:
          200:
            description: Ok
        """
        limit = request.args.get('limit', 1)
        workspace_name = kwargs.get('workspace_name')

        if workspace_name:
            workspace = get_workspace(workspace_name)
            data = db.session.query(User, func.count(VulnerabilityGeneric.id)).join(VulnerabilityGeneric.creator) \
                .filter(VulnerabilityGeneric.workspace_id == workspace.id).group_by(User.id) \
                .order_by(desc(func.count(VulnerabilityGeneric.id))).limit(int(limit)).all()
        else:
            data = self._apply_filter_context(
                db.session.query(User, func.count(VulnerabilityGeneric.id)).join(VulnerabilityGeneric.creator)
                .group_by(User.id)
            ).order_by(desc(func.count(VulnerabilityGeneric.id))).limit(int(limit)).all()

        users = []
        for item in data:
            user = {
                'id': item[0].id,
                'username': item[0].username,
                'count': item[1]
            }
            users.append(user)
        response = {'users': users}
        return jsonify(response)

    @route('', methods=['DELETE'])
    def bulk_delete(self, **kwargs):
        # TODO BULK_DELETE_SCHEMA
        if not request.json or 'severities' not in request.json:
            return super().bulk_delete(self, **kwargs)
        return self._perform_bulk_delete(request.json['severities'], by='severity', **kwargs), HTTP_OK
    bulk_delete.__doc__ = BulkDeleteMixin.bulk_delete.__doc__

    def _bulk_delete_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        if kwargs.get("by", "id") != "severity":
            query = self.model_class.query.filter(self.model_class.id.in_(ids))
        else:
            query = self.model_class.query.filter(self.model_class.severity.in_(ids))
        return self._apply_filter_context(query)

    def _get_model_association_proxy_fields(self):
        return [
            field.target_collection
            for field in inspect(self.model_class).all_orm_descriptors
            if field.extension_type.name == "ASSOCIATION_PROXY"
        ]

    def _pre_bulk_update(self, data, **kwargs):
        data.pop('type', '')  # It's forbidden to change vuln type!
        data.pop('tool', '')
        data.pop('service_id', '')
        data.pop('host_id', '')

        custom_behaviour_fields = {}

        # This fields (cvss2 and cvss3) are better to be processed in this way because the model parse
        # vector string into fields and calculates the scores
        if 'cvss2_vector_string' in data:
            custom_behaviour_fields['cvss2_vector_string'] = data.pop('cvss2_vector_string')
        if 'cvss3_vector_string' in data:
            custom_behaviour_fields['cvss3_vector_string'] = data.pop('cvss3_vector_string')
        if 'cvss4_vector_string' in data:
            custom_behaviour_fields['cvss_4_vector_string'] = data.pop('cvss4_vector_string')

        cwe_list = data.pop('cwe', None)
        if cwe_list is not None:
            custom_behaviour_fields['cwe'] = create_cwe(cwe_list)
        refs = data.pop('refs', None)
        if refs is not None:
            custom_behaviour_fields['refs'] = refs

        # TODO For now, we don't want to accept multiples attachments; moreover, attachments have its own endpoint
        data.pop('_attachments', [])
        super()._pre_bulk_update(data, **kwargs)

        model_association_proxy_fields = self._get_model_association_proxy_fields()
        for key in list(data):
            parent = getattr(VulnerabilityWeb, key).parent
            field_name = getattr(parent, "target_collection", None)
            if field_name and field_name in model_association_proxy_fields:
                custom_behaviour_fields[key] = data.pop(key)

        return custom_behaviour_fields

    def _post_bulk_update(self, ids, extracted_data, **kwargs):
        workspaces_and_ids = (db.session.query(Workspace, func.array_agg(VulnerabilityGeneric.id))
                              .join(VulnerabilityGeneric).filter(VulnerabilityGeneric.id.in_(ids))
                              .group_by(Workspace.id).all())

        if extracted_data:
            queryset = self._bulk_update_query(ids, **kwargs)
            for obj in queryset.all():
                for (key, value) in extracted_data.items():
                    if key == 'refs':
                        value = create_reference(value, obj.id)
                    setattr(obj, key, value)
                    db.session.add(obj)

        if workspaces_and_ids:
            for ws_vulns in workspaces_and_ids:
                ws_id = ws_vulns[0].id

                command = Command()
                command.workspace_id = ws_id
                command.user_id = current_user.id
                command.start_date = datetime.utcnow()
                command.tool = 'web_ui'
                command.command = 'bulk_update'
                db.session.add(command)
                db.session.commit()
                cobjects_list = []

                for id in ws_vulns[1]:
                    cobject_dict = {
                        "object_id": id,
                        "object_type": "vulnerability",
                        "command_id": command.id,
                        "workspace_id": ws_id,
                        "create_date": datetime.utcnow(),
                        "created_persistent": False
                    }
                    cobjects_list.append(cobject_dict)
                db.session.execute(sqlalchemy_insert(CommandObject).values(cobjects_list))
                db.session.commit()

        if 'returning' in kwargs and kwargs['returning']:
            # update host stats
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel
            host_id_list = [data[4] for data in kwargs['returning'] if data[4]]
            service_id_list = [data[5] for data in kwargs['returning'] if data[5]]
            if faraday_server.celery_enabled:
                update_host_stats.delay(host_id_list, service_id_list)
            else:
                update_host_stats(host_id_list, service_id_list)

        for workspace in [x[0] for x in workspaces_and_ids]:
            debounce_workspace_update(workspace.name)

    def _perform_bulk_delete(self, values, **kwargs):
        # Get host and service ids in order to update host stats
        host_ids = db.session.query(
            VulnerabilityGeneric.host_id,
            VulnerabilityGeneric.service_id
        )

        by_severity = kwargs.get('by', None) == 'severity'
        if by_severity:
            for severity in values:
                if severity not in VulnerabilityABC.SEVERITIES:
                    abort(HTTP_BAD_REQUEST, "Severity type not valid")

            host_ids = host_ids.filter(
                VulnerabilityGeneric.severity.in_(values)
            ).all()

            workspaces = (self._get_context_workspace_query(operation='write')
                          .join(VulnerabilityGeneric)
                          .filter(VulnerabilityGeneric.severity.in_(values))
                          .distinct(Workspace.id).all())
        else:
            host_ids = host_ids.filter(
                VulnerabilityGeneric.id.in_(values)
            ).all()

            workspaces = (self._get_context_workspace_query(operation='write')
                          .join(VulnerabilityGeneric)
                          .filter(VulnerabilityGeneric.id.in_(values))
                          .distinct(Workspace.id).all())

        response = super()._perform_bulk_delete(values, **kwargs)
        deleted = response.json.get('deleted', 0)
        if deleted > 0:
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel

            for workspace in workspaces:
                debounce_workspace_update(workspace.name)

            host_id_list = [data[0] for data in host_ids if data[0]]
            service_id_list = [data[1] for data in host_ids if data[1]]

            if faraday_server.celery_enabled:
                update_host_stats.delay(host_id_list, service_id_list)
            else:
                update_host_stats(host_id_list, service_id_list)

        return response

    def _paginate(self, query, hard_limit=0):
        limit = get_settings("query_limits").vuln_query_limit
        return super()._paginate(query, hard_limit=limit)


VulnerabilityView.register(vulns_api)
