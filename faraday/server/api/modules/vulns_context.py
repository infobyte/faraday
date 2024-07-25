"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import http
# Standard library imports
import io
import logging
import json
from json.decoder import JSONDecodeError

# Related third party imports
import flask
from flask import request, send_file
from flask import Blueprint, make_response
from flask_classful import route
from filteralchemy import operators
from marshmallow import ValidationError
from sqlalchemy import desc, func
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import joinedload, selectin_polymorphic, undefer, noload
from depot.manager import DepotManager

from faraday.server.config import faraday_server
from faraday.server.debouncer import debounce_workspace_update
# Local application imports
from faraday.server.utils.cwe import create_cwe
from faraday.server.utils.reference import create_reference
from faraday.server.utils.search import search
from faraday.server.api.base import (
    FilterAlchemyMixin,
    FilterSetMeta,
    PaginatedMixin,
    InvalidUsage,
    CountMultiWorkspacedMixin,
    get_filtered_data,
    BulkUpdateMixin,
    BulkDeleteMixin,
    ReadOnlyView,
    ContextMixin
)
from faraday.server.fields import FaradayUploadedFile
from faraday.server.models import (
    db,
    File,
    Host,
    Service,
    Vulnerability,
    VulnerabilityWeb,
    CustomFieldsSchema,
    VulnerabilityGeneric,
    User,
    Workspace,
    VulnerabilityABC,
)
from faraday.server.utils.database import (
    get_or_create,
)
from faraday.server.utils.export import export_vulns_to_csv
from faraday.server.utils.filters import FlaskRestlessSchema
from faraday.server.api.modules.vulns import (
    EvidenceSchema,
    VulnerabilitySchema,
    VulnerabilityWebSchema,
    CustomILike,
    VulnerabilityFilterSet
)

vulns_context_api = Blueprint('vulns_context_api', __name__)
logger = logging.getLogger(__name__)

# Use this override for filterset fields that filter by en exact match by
# default, and not by a similar one (like operator)
_strict_filtering = {'default_operator': operators.Equal}


class VulnerabilityContextFilterSet(VulnerabilityFilterSet):
    class Meta(FilterSetMeta):
        model = VulnerabilityWeb  # It has all the fields
        # TODO migration: Check if we should add fields owner,
        # command, impact, issuetracker, tags, date, host
        # evidence, policy violations, hostnames

        fields = (
            "id", "status", "website", "parameter_name", "query_string", "path", "service",
            "data", "severity", "confirmed", "name", "request", "response",
            "parameters", "resolution",
            "description", "command_id", "target", "creator", "method",
            "ease_of_resolution", "service_id",
            "status_code", "tool", 'workspace.name'
        )

        strict_fields = (
            "severity", "confirmed", "method", "status", "ease_of_resolution",
            "service_id",
        )

        default_operator = CustomILike
        # next line uses dict comprehensions!
        column_overrides = {
            field: _strict_filtering for field in strict_fields
        }
        operators = (CustomILike, operators.Equal)


# TODO ver si se usa CountMultiWorkspacedMixin
class VulnerabilityContextView(ContextMixin,
                        PaginatedMixin,
                        FilterAlchemyMixin,
                        ReadOnlyView,
                        CountMultiWorkspacedMixin,
                        BulkDeleteMixin,
                        BulkUpdateMixin):
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
        return super()._perform_bulk_update(ids, data, **kwargs)

    def _get_eagerloaded_query(self, *args, **kwargs):
        """Eager hostnames loading.

        This is too complex to get_joinedloads so I have to
        override the function
        """
        query = super()._get_eagerloaded_query(
            *args, **kwargs)
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

        if flask.request.args.get('get_evidence'):
            options.append(joinedload(VulnerabilityGeneric.evidence))
        else:
            options.append(noload(VulnerabilityGeneric.evidence))

        return query.options(selectin_polymorphic(
            VulnerabilityGeneric,
            [Vulnerability, VulnerabilityWeb]
        ), *options)

    def _filter_query(self, query):
        query = super()._filter_query(query)
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
        # TODO hay que hacer foco en esto
        if request.method == 'POST' and request.json:
            return self.model_class_dict[request.json['type']]
        # We use Generic to list all vulns from all types
        return self.model_class_dict['VulnerabilityGeneric']

    def _get_schema_class(self):
        assert self.schema_class_dict is not None, "You must define schema_class"
        if request.method == 'POST' and request.json:
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
                group['severity'] = group['name'] = severity_map.get(
                    severity, severity)
            elif type == "confirmed":
                confirmed_map = {
                    1: "True",
                    0: "False"
                }
                confirmed = group[type]
                group[type] = group['name'] = confirmed_map.get(
                    confirmed, confirmed)
            else:
                group['name'] = group[type]
            return group

        if request.args.get('group_by') == 'severity':
            res['groups'] = [convert_group(group, 'severity') for group in res['groups']]
        if request.args.get('group_by') == 'confirmed':
            res['groups'] = [convert_group(group, 'confirmed') for group in res['groups']]
        return res

    @route('/<int:vuln_id>/attachment', methods=['POST'])
    def post_attachment(self, vuln_id):
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
            flask.abort(404, "Vulnerability not found")
        if 'file' not in request.files:
            flask.abort(400)
        vuln = VulnerabilitySchema().dump(vuln_permission_check)
        filename = request.files['file'].filename
        _attachments = vuln['_attachments']
        if filename in _attachments:
            message = 'Evidence already exists in vuln'
            return make_response(flask.jsonify(message=message, success=False, code=400), 400)

        faraday_file = FaradayUploadedFile(request.files['file'].read())
        instance, created = get_or_create(
            db.session,
            File,
            object_id=vuln_id,
            object_type='vulnerability',
            name=filename,
            filename=filename,
            content=faraday_file
        )
        db.session.commit()
        message = 'Evidence upload was successful'
        logger.info(message)
        return flask.jsonify({'message': message})

    @route('/filter')
    def filter(self):
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
        filters = request.args.get('q', '{}')
        export_csv = request.args.get('export_csv', '')
        filtered_vulns, count = self._filter(filters, exclude_list=(
            '_attachments',
            'desc'
        ) if export_csv.lower() == 'true' else None)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        if export_csv.lower() == 'true':
            custom_fields_columns = []
            for custom_field in db.session.query(CustomFieldsSchema).order_by(CustomFieldsSchema.field_order):
                custom_fields_columns.append(custom_field.field_name)
            memory_file = export_vulns_to_csv(filtered_vulns, custom_fields_columns)
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
                    "val": argument,

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

    def _generate_filter_query(self, vulnerability_class, filters, hostname_filters, marshmallow_params, is_csv=False):
        hosts_os_filter = [host_os_filter for host_os_filter in filters.get('filters', []) if
                           host_os_filter.get('name') == 'host__os']

        if hosts_os_filter:
            # remove host__os filters from filters due to a bug
            hosts_os_filter = hosts_os_filter[0]
            filters['filters'] = [host_os_filter for host_os_filter in filters.get('filters', []) if
                                  host_os_filter.get('name') != 'host__os']

        vulns = search(db.session,
                       vulnerability_class,
                       filters)
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
                    joinedload('refs')
                ]

            vulns = vulns.options(selectin_polymorphic(
                VulnerabilityGeneric,
                [Vulnerability, VulnerabilityWeb]
            ), *options)
        return vulns

    def _filter(self, filters, exclude_list=None):
        hostname_filters = []
        vulns = None
        try:
            filters = FlaskRestlessSchema().load(json.loads(filters)) or {}
            if filters:
                filters['filters'], hostname_filters = self._hostname_filters(filters.get('filters', []))
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            flask.abort(400, "Invalid filters")

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
        )if not exclude_list else exclude_list}
        if 'group_by' not in filters:
            offset = None
            limit = None
            if 'offset' in filters:
                offset = filters.pop('offset')
            if 'limit' in filters:
                limit = filters.pop('limit')  # we need to remove pagination, since

            try:
                vulns = self._generate_filter_query(
                    VulnerabilityGeneric,
                    filters,
                    hostname_filters,
                    marshmallow_params,
                    bool(exclude_list))
            except AttributeError as e:
                flask.abort(400, e)
            total_vulns = vulns.order_by(None)
            if limit:
                vulns = vulns.limit(limit)
            if offset:
                vulns = vulns.offset(offset)

            vulns = self.schema_class_dict['VulnerabilityWeb'](**marshmallow_params).dump(vulns)
            return vulns, total_vulns.count()
        else:
            vulns = self._generate_filter_query(
                VulnerabilityGeneric,
                filters,
                hostname_filters,
                marshmallow_params,
            )
            vulns_data, rows_count = get_filtered_data(filters, vulns)

            return vulns_data, rows_count

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['GET'])
    def get_attachment(self, vuln_id, attachment_filename):
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

        if not vuln_permission_check:
            flask.abort(404, "Vulnerability not found")

        file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                                    object_id=vuln_id,
                                                    filename=attachment_filename.replace(" ", "%20")).first()
        if not file_obj:
            flask.abort(404, "File not found")

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

    @route('/<int:vuln_id>/attachment', methods=['GET'])
    def get_attachments_by_vuln(self, vuln_id):
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
            flask.abort(404, "Vulnerability not found")
        files = db.session.query(File).filter_by(object_type='vulnerability',
                                                 object_id=vuln_id).all()
        res = {}
        for file_obj in files:
            ret = EvidenceSchema().dump(file_obj)
            res[file_obj.filename] = ret

        return flask.jsonify(res)

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['DELETE'])
    def delete_attachment(self, vuln_id, attachment_filename):
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
            flask.abort(404, "Vulnerability not found")
        file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                                    object_id=vuln_id,
                                                    filename=attachment_filename).first()
        if not file_obj:
            flask.abort(404, "File not found")
        db.session.delete(file_obj)
        db.session.commit()
        depot = DepotManager.get()
        depot.delete(file_obj.content.get('file_id'))
        message = 'Attachment was successfully deleted'
        logger.info(message)
        return flask.jsonify({'message': message})

    @route('export_csv', methods=['GET'])
    def export_csv(self):
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
            filters = json.dumps(filters)
        vulns_query, _ = self._filter(filters)
        memory_file = export_vulns_to_csv(vulns_query, custom_fields_columns)
        logger.info("csv file exported with context vulns")
        return send_file(memory_file,
                         attachment_filename="Faraday-SR-Context.csv",
                         as_attachment=True,
                         cache_timeout=-1)

    @route('top_users', methods=['GET'])
    def top_users(self):
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
        limit = flask.request.args.get('limit', 1)
        data = self._apply_filter_context(
            db.session.query(User, func.count(VulnerabilityGeneric.id)).join(VulnerabilityGeneric.creator)
            .group_by(User.id)
            .order_by(desc(func.count(VulnerabilityGeneric.id))).limit(int(limit))
        ).all()
        users = []
        for item in data:
            user = {
                'id': item[0].id,
                'username': item[0].username,
                'count': item[1]
            }
            users.append(user)
        response = {'users': users}
        return flask.jsonify(response)

    @route('', methods=['DELETE'])
    def bulk_delete(self, **kwargs):
        if not flask.request.json or 'severities' not in flask.request.json:
            return super().bulk_delete(self, **kwargs)
        return self._perform_bulk_delete(flask.request.json['severities'], by='severity', **kwargs), 200
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
        workspaces = Workspace.query.join(VulnerabilityGeneric).filter(VulnerabilityGeneric.id.in_(ids)).distinct(Workspace.id).all()
        if extracted_data:
            queryset = self._bulk_update_query(ids, **kwargs)
            for obj in queryset.all():
                for (key, value) in extracted_data.items():
                    if key == 'refs':
                        value = create_reference(value, obj.id)
                    setattr(obj, key, value)
                    db.session.add(obj)

        if 'returning' in kwargs and kwargs['returning']:
            # update host stats
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel
            host_id_list = [data[4] for data in kwargs['returning'] if data[4]]
            service_id_list = [data[5] for data in kwargs['returning'] if data[5]]
            if faraday_server.celery_enabled:
                update_host_stats.delay(host_id_list, service_id_list)
            else:
                update_host_stats(host_id_list, service_id_list)

        for workspace in workspaces:
            debounce_workspace_update(workspace.name)

    def _perform_bulk_delete(self, values, **kwargs):
        # Get host and service ids in order to update host stats
        host_ids = db.session.query(
            VulnerabilityGeneric.host_id,
            VulnerabilityGeneric.service_id
        )

        if kwargs.get("by", "id") != "severity":
            workspaces = self._get_context_workspace_query(operation='write').join(VulnerabilityGeneric).filter(VulnerabilityGeneric.id.in_(values)).distinct(Workspace.id).all()
        else:
            workspaces = self._get_context_workspace_query(operation='write').join(VulnerabilityGeneric).filter(VulnerabilityGeneric.severity.in_(values)).distinct(Workspace.id).all()
        by_severity = kwargs.get('by', None)
        if by_severity == 'severity':
            for severity in values:
                if severity not in VulnerabilityABC.SEVERITIES:
                    flask.abort(http.client.BAD_REQUEST, "Severity type not valid")

            host_ids = host_ids.filter(
                VulnerabilityGeneric.severity.in_(values)
            ).all()
        else:
            host_ids = host_ids.filter(
                VulnerabilityGeneric.id.in_(values)
            ).all()

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


VulnerabilityContextView.register(vulns_context_api)
