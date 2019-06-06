# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import io
import json
import logging
from base64 import b64encode, b64decode

import flask
import wtforms
from filteralchemy import Filter, FilterSet, operators
from flask import request
from flask import Blueprint
from flask_classful import route
from flask_restless.search import search
from flask_wtf.csrf import validate_csrf
from marshmallow import Schema, fields, post_load, ValidationError
from marshmallow.validate import OneOf
from sqlalchemy.orm import aliased, joinedload, selectin_polymorphic, undefer
from sqlalchemy.orm.exc import NoResultFound

from depot.manager import DepotManager
from faraday.server.api.base import (
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
    PaginatedMixin,
    ReadWriteWorkspacedView,
    InvalidUsage)
from faraday.server.fields import FaradayUploadedFile
from faraday.server.models import (
    db,
    File,
    Host,
    Service,
    Hostname,
    Workspace,
    Vulnerability,
    VulnerabilityWeb,
    VulnerabilityGeneric,
)
from faraday.server.utils.database import get_or_create

from faraday.server.api.modules.services import ServiceSchema
from faraday.server.schemas import (
    MutableField,
    SeverityField,
    MetadataSchema,
    SelfNestedField,
    FaradayCustomField,
    PrimaryKeyRelatedField,
)

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
    accountability = fields.Boolean(attribute='impact_accountability', default=False)
    availability = fields.Boolean(attribute='impact_availability', default=False)
    confidentiality = fields.Boolean(attribute='impact_confidentiality', default=False)
    integrity = fields.Boolean(attribute='impact_integrity', default=False)


class CustomMetadataSchema(MetadataSchema):
    """
    Implements command_id and creator logic
    """
    command_id = fields.Integer(dump_only=True, attribute='creator_command_id')
    creator = fields.Method('get_creator', dump_only=True)

    def get_creator(self, obj):
        return obj.creator_command_tool or 'Web UI'


class VulnerabilitySchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')

    _rev = fields.String(dump_only=True, default='')
    _attachments = fields.Method(serialize='get_attachments', deserialize='load_attachments', default=[])
    owned = fields.Boolean(dump_only=True, default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    impact = SelfNestedField(ImpactSchema())
    desc = fields.String(attribute='description')
    description = fields.String(dump_only=True)
    policyviolations = fields.List(fields.String,
                                   attribute='policy_violations')
    refs = fields.List(fields.String(), attribute='references')
    issuetracker = fields.Method(serialize='get_issuetracker', dump_only=True)
    parent = fields.Method(serialize='get_parent', deserialize='load_parent', required=True)
    parent_type = MutableField(fields.Method('get_parent_type'),
                               fields.String(),
                               required=True)
    tags = PrimaryKeyRelatedField('name', dump_only=True, many=True)
    easeofresolution = fields.String(
        attribute='ease_of_resolution',
        validate=OneOf(Vulnerability.EASE_OF_RESOLUTIONS),
        allow_none=True)
    hostnames = PrimaryKeyRelatedField('name', many=True, dump_only=True)
    service = fields.Nested(ServiceSchema(only=[
        '_id', 'ports', 'status', 'protocol', 'name', 'version', 'summary'
    ]), dump_only=True)
    host = fields.Integer(dump_only=True, attribute='host_id')
    severity = SeverityField(required=True)
    status = fields.Method(
        serialize='get_status',
        validate=OneOf(Vulnerability.STATUSES + ['opened']),
        deserialize='load_status')
    type = fields.Method(serialize='get_type',
                         deserialize='load_type',
                         required=True)
    obj_id = fields.String(dump_only=True, attribute='id')
    target = fields.String(dump_only=True, attribute='target_host_ip')
    host_os = fields.String(dump_only=True, attribute='target_host_os')
    metadata = SelfNestedField(CustomMetadataSchema())
    date = fields.DateTime(attribute='create_date',
                           dump_only=True)  # This is only used for sorting
    custom_fields = FaradayCustomField(table_name='vulnerability', attribute='custom_fields')

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
            'target', 'host_os', 'resolution', 'metadata',
            'custom_fields')

    def get_type(self, obj):
        return obj.__class__.__name__

    def get_attachments(self, obj):
        res = {}

        for file_obj in obj.evidence:
            try:
                ret, errors = EvidenceSchema().dump(file_obj)
                if errors:
                    raise ValidationError(errors, data=ret)
                res[file_obj.filename] = ret
            except IOError:
                logger.warning("File not found. Did you move your server?")

        return res

    def load_attachments(self, value):
        return value

    def get_parent(self, obj):
        return obj.service_id or obj.host_id

    def get_parent_type(self, obj):
        assert obj.service_id is not None or obj.host_id is not None
        return 'Service' if obj.service_id is not None else 'Host'

    def get_status(self, obj):
        if obj.status == 'open':
            return 'opened'
        return obj.status

    def get_issuetracker(self, obj):
        return {}

    def load_status(self, value):
        if value == 'opened':
            return 'open'
        return value

    def load_type(self, value):
        if value == 'Vulnerability':
            return 'vulnerability'
        if value == 'VulnerabilityWeb':
            return 'vulnerability_web'
        else:
            raise ValidationError('Invalid vulnerability type.')

    def load_parent(self, value):
        try:
            # sometimes api requests send str or unicode.
            value = int(value)
        except ValueError:

            raise ValidationError("Invalid parent type")
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
            raise ValidationError('Unknown parent type')
        if parent_type == 'Host' and data['type'] == 'vulnerability_web':
            raise ValidationError('Trying to set a host for a vulnerability web')

        try:
            parent = db.session.query(parent_class).join(Workspace).filter(
                Workspace.name == self.context['workspace_name'],
                parent_class.id == parent_id
            ).one()
        except NoResultFound:
            raise ValidationError('Parent id not found: {}'.format(parent_id))
        data[parent_field] = parent.id
        # TODO migration: check what happens when updating the parent from
        # service to host or viceverse
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
        fields = (
            '_id', 'status', 'parent_type',
            'website', 'issuetracker', 'description', 'parent',
            'tags', 'severity', '_rev', 'easeofresolution', 'owned',
            'hostnames', 'pname', 'query', 'owner',
            'path', 'date', 'data', 'response', 'refs',
            'desc', 'impact', 'confirmed', 'name',
            'service', 'obj_id', 'type', 'policyviolations',
            'request', '_attachments', 'params',
            'target', 'host_os', 'resolution', 'method', 'metadata',
            'status_code', 'custom_fields'
        )


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
        return query.filter(model.target_host_ip.ilike("%" + value + "%"))


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

        service_hostnames_query = query.join(Service, Service.id == Vulnerability.service_id).\
           join(Host).\
           join(alias).\
           filter(alias.name.in_(value_list))

        host_hostnames_query = query.join(Host, Host.id == Vulnerability.host_id).\
            join(alias).\
            filter(alias.name.in_(value_list))

        query = service_hostnames_query.union(host_hostnames_query)
        return query


class CustomILike(operators.Operator):
    """A filter operator that puts a % in the beggining and in the
    end of the search string to force a partial search"""

    def __call__(self, query, model, attr, value):
        column = getattr(model, attr)
        condition = column.ilike('%' + value + '%')
        return query.filter(condition)


class VulnerabilityFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = VulnerabilityWeb  # It has all the fields
        # TODO migration: Check if we should add fields owner,
        # command, impact, issuetracker, tags, date, host
        # evidence, policy violations, hostnames
        fields = (
            "id", "status", "website", "pname", "query", "path", "service",
            "data", "severity", "confirmed", "name", "request", "response",
            "parameters", "params", "resolution", "ease_of_resolution",
            "description", "command_id", "target", "creator", "method",
            "easeofresolution", "query_string", "parameter_name", "service_id",
            "status_code"
        )

        strict_fields = (
            "severity", "confirmed", "method", "status", "easeofresolution",
            "ease_of_resolution", "service_id",
        )

        default_operator = CustomILike
        # next line uses dict comprehensions!
        column_overrides = {
            field: _strict_filtering for field in strict_fields
        }
        operators = (CustomILike, operators.Equal)
    id = IDFilter(fields.Int())
    target = TargetFilter(fields.Str())
    type = TypeFilter(fields.Str(validate=[OneOf(['Vulnerability',
                                                  'VulnerabilityWeb'])]))
    creator = CreatorFilter(fields.Str())
    service = ServiceFilter(fields.Str())
    severity = Filter(SeverityField())
    easeofresolution = Filter(fields.String(
        attribute='ease_of_resolution',
        validate=OneOf(Vulnerability.EASE_OF_RESOLUTIONS),
        allow_none=True))
    pname = Filter(fields.String(attribute='parameter_name'))
    query = Filter(fields.String(attribute='query_string'))
    status_code = StatusCodeFilter(fields.Int())
    params = Filter(fields.String(attribute='parameters'))
    status = Filter(fields.Function(
        deserialize=lambda val: 'open' if val == 'opened' else val,
        validate=OneOf(Vulnerability.STATUSES + ['opened'])
    ))
    hostnames = HostnamesFilter(fields.Str())
    confirmed = Filter(fields.Boolean())

    def filter(self):
        """Generate a filtered query from request parameters.

        :returns: Filtered SQLALchemy query
        """
        # TODO migration: this can became a normal filter instead of a custom
        # one, since now we can use creator_command_id
        command_id = request.args.get('command_id')
        query = super(VulnerabilityFilterSet, self).filter()

        if command_id:
            # query = query.filter(CommandObject.command_id == int(command_id))
            query = query.filter(VulnerabilityGeneric.creator_command_id ==
                                 int(command_id))  # TODO migration: handle invalid int()
        return query


class VulnerabilityView(PaginatedMixin,
                        FilterAlchemyMixin,
                        ReadWriteWorkspacedView):
    route_base = 'vulns'
    filterset_class = VulnerabilityFilterSet
    sort_model_class = VulnerabilityWeb  # It has all the fields
    sort_pass_silently = True  # For compatibility with the Web UI
    unique_fields_by_class = {
        'Vulnerability': [('name', 'description', 'host_id', 'service_id')],
        'VulnerabilityWeb': [('name', 'description', 'service_id', 'method',
                              'parameter_name', 'path', 'website')],
    }

    model_class_dict = {
        'Vulnerability': Vulnerability,
        'VulnerabilityWeb': VulnerabilityWeb,
        'VulnerabilityGeneric': VulnerabilityGeneric,  # For listing objects
    }
    schema_class_dict = {
        'Vulnerability': VulnerabilitySchema,
        'VulnerabilityWeb': VulnerabilityWebSchema
    }

    def _validate_uniqueness(self, obj, object_id=None):
        unique_fields = self.unique_fields_by_class[obj.__class__.__name__]
        super(VulnerabilityView, self)._validate_uniqueness(
            obj, object_id, unique_fields)

    def _perform_create(self, data, **kwargs):
        data = self._parse_data(self._get_schema_instance(kwargs),
                                request)
        # TODO migration: use default values when popping and validate the
        # popped object has the expected type.
        # This will be set after setting the workspace
        attachments = data.pop('_attachments', {})
        references = data.pop('references', [])
        policyviolations = data.pop('policy_violations', [])

        try:
            obj = super(VulnerabilityView, self)._perform_create(data, **kwargs)
        except TypeError:
            # TypeError is raised when trying to instantiate an sqlalchemy model
            # with invalid attributes, for example VulnerabilityWeb with host_id
            flask.abort(400)

        obj.references = references
        obj.policy_violations = policyviolations
        db.session.commit()
        self._process_attachments(obj, attachments)
        return obj

    def _process_attachments(self, obj, attachments):
        old_attachments = db.session.query(File).filter_by(
            object_id=obj.id,
            object_type='vulnerability',
        )
        for old_attachment in old_attachments:
            db.session.delete(old_attachment)
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

    def _update_object(self, obj, data):
        data.pop('type') # It's forbidden to change vuln type!
        return super(VulnerabilityView, self)._update_object(obj, data)

    def _perform_update(self, object_id, obj, data, workspace_name):
        attachments = data.pop('_attachments', {})
        obj = super(VulnerabilityView, self)._perform_update(object_id, obj, data, workspace_name)
        db.session.flush()
        self._process_attachments(obj, attachments)
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
            joinedload(VulnerabilityGeneric.update_user),
            undefer(VulnerabilityGeneric.creator_command_id),
            undefer(VulnerabilityGeneric.creator_command_tool),
            undefer(VulnerabilityGeneric.target_host_ip),
            undefer(VulnerabilityGeneric.target_host_os),
            joinedload(VulnerabilityGeneric.evidence),
            joinedload(VulnerabilityGeneric.tags),
        ]
        return query.options(selectin_polymorphic(
            VulnerabilityGeneric,
            [Vulnerability, VulnerabilityWeb]
        ), *joinedloads)

    def _filter_query(self, query):
        query = super(VulnerabilityView, self)._filter_query(query)
        search_term = flask.request.args.get('search', None)
        if search_term is not None:
            # TODO migration: add more fields to free text search
            like_term = '%' + search_term + '%'
            match_name = VulnerabilityGeneric.name.ilike(like_term)
            match_desc = VulnerabilityGeneric.description.ilike(like_term)
            query = query.filter(match_name | match_desc)
        return query

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
                raise InvalidUsage('Type is required.')
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

    @route('/<int:vuln_id>/attachment/', methods=['POST'])
    def post_attachment(self, workspace_name, vuln_id):
        try:
            validate_csrf(request.form.get('csrf_token'))
        except wtforms.ValidationError:
            flask.abort(403)
        vuln_workspace_check = db.session.query(VulnerabilityGeneric, Workspace.id).join(
            Workspace).filter(VulnerabilityGeneric.id == vuln_id,
                                Workspace.name == workspace_name).first()

        if vuln_workspace_check:
            if 'file' not in request.files:
                flask.abort(400)

            faraday_file = FaradayUploadedFile(request.files['file'].read())
            filename = request.files['file'].filename

            get_or_create(
                db.session,
                File,
                object_id=vuln_id,
                object_type='vulnerability',
                name=filename,
                filename=filename,
                content=faraday_file
            )
            db.session.commit()
            return flask.jsonify({'message': 'Evidence upload was successful'})
        else:
            flask.abort(404, "Vulnerability not found")

    @route('/filter')
    def filter(self, workspace_name):
        try:
            filters = json.loads(request.args.get('q'))
        except ValueError as ex:
            flask.abort(400, "Invalid filters")

        workspace = self._get_workspace(workspace_name)
        marshmallow_params = {'many': True, 'context': {}, 'strict': True}
        try:
            normal_vulns = search(db.session,
                                  Vulnerability,
                                  filters)
            normal_vulns = normal_vulns.filter_by(workspace_id=workspace.id)
            normal_vulns = self.schema_class_dict['VulnerabilityWeb'](**marshmallow_params).dumps(normal_vulns.all())
            normal_vulns_data = json.loads(normal_vulns.data)
        except Exception:
            normal_vulns_data = []
        try:
            web_vulns = search(db.session,
                           VulnerabilityWeb,
                           filters)
            web_vulns = web_vulns.filter_by(workspace_id=workspace.id)
            web_vulns = self.schema_class_dict['VulnerabilityWeb'](**marshmallow_params).dumps(web_vulns.all())
            web_vulns_data = json.loads(web_vulns.data)
        except Exception:
            web_vulns_data = []
        return self._envelope_list(normal_vulns_data + web_vulns_data)

    @route('/<int:vuln_id>/attachment/<attachment_filename>/', methods=['GET'])
    def get_attachment(self, workspace_name, vuln_id, attachment_filename):
        vuln_workspace_check = db.session.query(VulnerabilityGeneric, Workspace.id).join(
            Workspace).filter(VulnerabilityGeneric.id == vuln_id,
                              Workspace.name == workspace_name).first()
        if vuln_workspace_check:
            file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                         object_id=vuln_id,
                                         filename=attachment_filename).first()
            if file_obj:
                depot = DepotManager.get()
                depot_file = depot.get(file_obj.content.get('file_id'))
                if depot_file.content_type.startswith('image/'):
                    # Image content types are safe (they can't be executed like
                    # html) so we don't have to force the download of the file
                    as_attachment = False
                else:
                    as_attachment = True
                return flask.send_file(
                    io.BytesIO(depot_file.read()),
                    attachment_filename=file_obj.filename,
                    as_attachment=as_attachment,
                    mimetype=depot_file.content_type
                )
            else:
                flask.abort(404, "File not found")
        else:
            flask.abort(404, "Vulnerability not found")

    @route('/<int:vuln_id>/attachments/', methods=['GET'])
    def get_attachments_by_vuln(self, workspace_name, vuln_id):
        workspace = self._get_workspace(workspace_name)
        vuln_workspace_check = db.session.query(VulnerabilityGeneric, Workspace.id).join(
            Workspace).filter(VulnerabilityGeneric.id == vuln_id,
                              Workspace.name == workspace.name).first()
        if vuln_workspace_check:
            files = db.session.query(File).filter_by(object_type='vulnerability',
                                                        object_id=vuln_id).all()
            res = {}
            for file_obj in files:
                ret, errors = EvidenceSchema().dump(file_obj)
                if errors:
                    raise ValidationError(errors, data=ret)
                res[file_obj.filename] = ret

            return flask.jsonify(res)
        else:
            flask.abort(404, "Vulnerability not found")


    @route('/<int:vuln_id>/attachment/<attachment_filename>/', methods=['DELETE'])
    def delete_attachment(self, workspace_name, vuln_id, attachment_filename):
        vuln_workspace_check = db.session.query(VulnerabilityGeneric, Workspace.id).join(
            Workspace).filter(
            VulnerabilityGeneric.id == vuln_id, Workspace.name == workspace_name).first()

        if vuln_workspace_check:
            file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                                        object_id=vuln_id,
                                                        filename=attachment_filename).first()
            if file_obj:
                db.session.delete(file_obj)
                db.session.commit()
                depot = DepotManager.get()
                depot.delete(file_obj.content.get('file_id'))
                return flask.jsonify({'message': 'Attachment was successfully deleted'})
            else:
                flask.abort(404, "File not found")
        else:
            flask.abort(404, "Vulnerability not found")


VulnerabilityView.register(vulns_api)
