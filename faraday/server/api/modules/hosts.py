"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import logging
import csv
import re
from io import StringIO

# Related third party imports
import wtforms
import pytz
import flask
from flask import Blueprint, make_response, jsonify, abort
from flask_classful import route
from flask_wtf.csrf import validate_csrf
from marshmallow import fields, Schema
from filteralchemy import Filter, FilterSet, operators
from sqlalchemy import desc
from sqlalchemy.orm import joinedload, undefer

# Local application imports
from faraday.server.utils.database import get_or_create
from faraday.server.utils.command import set_command_id
from faraday.server.api.base import (
    ReadWriteWorkspacedView,
    PaginatedMixin,
    AutoSchema,
    FilterAlchemyMixin,
    FilterSetMeta,
    FilterWorkspacedMixin,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin, CountMultiWorkspacedMixin, get_workspace,
)
from faraday.server.api.modules.services import ServiceSchema
from faraday.server.schemas import (
    MetadataSchema,
    MutableField,
    NullToBlankString,
    PrimaryKeyRelatedField,
    SelfNestedField,
)
from faraday.server.models import Host, Service, db, Hostname, CommandObject, Command
from faraday.server.debouncer import debounce_workspace_update

host_api = Blueprint('host_api', __name__)
logger = logging.getLogger(__name__)


def get_total_count(obj):
    return obj.vulnerability_critical_generic_count + obj.vulnerability_high_generic_count \
           + obj.vulnerability_medium_generic_count + obj.vulnerability_low_generic_count \
           + obj.vulnerability_info_generic_count + obj.vulnerability_unclassified_generic_count


class HostCountSchema(Schema):
    host_id = fields.Integer(dump_only=True, allow_none=False, attribute='id')
    critical = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_critical_generic_count')
    high = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_high_generic_count')
    med = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_medium_generic_count')
    low = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_low_generic_count')
    info = fields.Integer(dump_only=True, allow_none=False, attribute='vulnerability_info_generic_count')
    unclassified = fields.Integer(dump_only=True, allow_none=False,
                                  attribute='vulnerability_unclassified_generic_count')
    total = fields.Function(get_total_count, dump_only=True)


class HostSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    id = fields.Integer()
    _rev = fields.String(default='', dump_only=True)
    ip = fields.String(default='')
    description = fields.String(required=True)  # Explicitly set required=True
    default_gateway = NullToBlankString(
        attribute="default_gateway_ip", required=False)
    name = fields.String(dump_only=True, attribute='ip', default='')
    os = fields.String(default='')
    owned = fields.Boolean(default=False)
    owner = PrimaryKeyRelatedField('username', attribute='creator', dump_only=True)
    services = fields.Integer(attribute='open_service_count', dump_only=True)
    credentials = fields.Integer(attribute='credentials_count', dump_only=True)
    hostnames = MutableField(
        PrimaryKeyRelatedField('name', many=True,
                               attribute="hostnames",
                               dump_only=True,
                               default=[]),
        fields.List(fields.String))
    metadata = SelfNestedField(MetadataSchema())
    type = fields.Function(lambda obj: 'Host', dump_only=True)
    service_summaries = fields.Method('get_service_summaries', dump_only=True)
    versions = fields.Method('get_service_version', dump_only=True)
    importance = fields.Integer(default=0, validate=lambda stars: stars in [0, 1, 2, 3])
    severity_counts = SelfNestedField(HostCountSchema(), dump_only=True)
    command_id = fields.Int(required=False, load_only=True)
    vulns = fields.Function(get_total_count, dump_only=True)
    workspace_name = fields.String(attribute='workspace.name', dump_only=True)

    class Meta:
        model = Host
        fields = ('id', '_id', '_rev', 'ip', 'description', 'mac',
                  'credentials', 'default_gateway', 'metadata',
                  'name', 'os', 'owned', 'owner', 'services', 'vulns',
                  'hostnames', 'type', 'service_summaries', 'versions',
                  'importance', 'severity_counts', 'command_id', 'workspace_name'
                  )

    @staticmethod
    def get_service_summaries(obj):
        return [service.summary
                for service in obj.services
                if service.status == 'open']

    @staticmethod
    def get_service_version(obj):
        return [service.version
                for service in obj.services
                if service.status == 'open']


class ServiceNameFilter(Filter):
    """Filter hosts by service name"""

    def filter(self, query, model, attr, value):
        return query.filter(model.services.any(Service.name == value))


class ServicePortFilter(Filter):
    """Filter hosts by service port"""

    def filter(self, query, model, attr, value):
        try:
            return query.filter(model.services.any(Service.port == int(value)))
        except ValueError:
            return query.filter(None)


class HostFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Host
        fields = ('id', 'ip', 'name', 'os', 'service', 'port')
        operators = (operators.Equal, operators.Like, operators.ILike)
    service = ServiceNameFilter(fields.Str())
    port = ServicePortFilter(fields.Str())


class HostsView(PaginatedMixin,
                FilterAlchemyMixin,
                ReadWriteWorkspacedView,
                FilterWorkspacedMixin,
                CountMultiWorkspacedMixin,
                BulkDeleteWorkspacedMixin,
                BulkUpdateWorkspacedMixin):
    route_base = 'hosts'
    model_class = Host
    order_field = desc(Host.vulnerability_critical_generic_count), \
        desc(Host.vulnerability_high_generic_count), \
        desc(Host.vulnerability_medium_generic_count), \
        desc(Host.vulnerability_low_generic_count), \
        desc(Host.vulnerability_info_generic_count), \
        desc(Host.vulnerability_unclassified_generic_count), Host.ip.asc()

    schema_class = HostSchema
    filterset_class = HostFilterSet
    get_undefer = [Host.credentials_count,
                   Host.open_service_count,
                   Host.vulnerability_critical_generic_count,
                   Host.vulnerability_high_generic_count,
                   Host.vulnerability_medium_generic_count,
                   Host.vulnerability_low_generic_count,
                   Host.vulnerability_info_generic_count,
                   Host.vulnerability_unclassified_generic_count,
                   ]
    get_joinedloads = [Host.hostnames, Host.services, Host.update_user]

    def _get_eagerloaded_query(self, *args, **kwargs):
        """
        Overrides _get_eagerloaded_query of GenericView
        """
        options = []
        try:
            has_creator = 'owner' in self._get_schema_class().opts.fields
        except AttributeError:
            has_creator = False
        show_stats = kwargs.pop('show_stats', True)
        if has_creator:
            # APIs for objects with metadata always return the creator's
            # username. Do a joinedload to prevent doing one query per object
            # (n+1) problem
            options.append(joinedload(
                getattr(self.model_class, 'creator')).load_only('username'))
        query = self._get_base_query(*args, **kwargs)
        options += [joinedload(relationship)
                    for relationship in self.get_joinedloads]
        if show_stats:
            options += [undefer(column) for column in self.get_undefer]
        return query.options(*options)

    def index(self, **kwargs):
        """
          ---
          get:
            summary: "Get a list of hosts."
            tags: ["Host"]
            responses:
              200:
                description: Ok
                content:
                  application/json:
                    schema: HostSchema
          tags: ["Host"]
          responses:
            200:
              description: Ok
        """
        kwargs['show_stats'] = flask.request.args.get('stats', '') != 'false'

        if not kwargs['show_stats']:
            kwargs['exclude'] = ['severity_counts', 'vulns', 'credentials', 'services']

        return super().index(**kwargs)

    @route('/filter')
    def filter(self, workspace_name):
        """
        ---
        get:
          tags: ["Filter", "Host"]
          description: Filters, sorts and groups hosts using a json with parameters. These parameters must be part of the model.
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
        tags: ["Filter", "Host"]
        responses:
          200:
            description: Ok
        """
        filters = flask.request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters, workspace_name, severity_count=True)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_objs, pagination_metadata)

    @route('/bulk_create', methods=['POST'])
    def bulk_create(self, workspace_name):
        """
        ---
        post:
          tags: ["Bulk", "Host"]
          description: Creates hosts in bulk
          responses:
            201:
              description: Created
              content:
                application/json:
                  schema: HostSchema
            400:
              description: Bad request
            403:
              description: Forbidden
        tags: ["Bulk", "Host"]
        responses:
          200:
            description: Ok
        """
        try:
            validate_csrf(flask.request.form.get('csrf_token'))
        except wtforms.ValidationError:
            flask.abort(403)

        def parse_hosts(list_string):
            items = re.findall(r"([.a-zA-Z0-9_-]+)", list_string)
            return items

        workspace = get_workspace(workspace_name)

        logger.info("Create hosts from CSV")
        if 'file' not in flask.request.files:
            abort(400, "Missing File in request")
        hosts_file = flask.request.files['file']
        stream = StringIO(hosts_file.stream.read().decode("utf-8"), newline=None)
        FILE_HEADERS = {'description', 'hostnames', 'ip', 'os'}
        try:
            hosts_reader = csv.DictReader(stream)
            if set(hosts_reader.fieldnames) != FILE_HEADERS:
                logger.error("Missing Required headers in CSV (%s)", FILE_HEADERS)
                abort(400, f"Missing Required headers in CSV ({FILE_HEADERS})")
            hosts_created_count = 0
            hosts_with_errors_count = 0
            for host_dict in hosts_reader:
                try:
                    hostnames = parse_hosts(host_dict.pop('hostnames'))
                    other_fields = {'owned': False, 'mac': '00:00:00:00:00:00', 'default_gateway_ip': 'None'}
                    host_dict.update(other_fields)
                    host = super()._perform_create(host_dict, workspace_name)
                    host.workspace = workspace
                    for name in hostnames:
                        get_or_create(db.session, Hostname, name=name, host=host, workspace=host.workspace)
                    db.session.commit()
                except Exception as e:
                    logger.error("Error creating host (%s)", e)
                    hosts_with_errors_count += 1
                else:
                    logger.debug("Host Created (%s)", host_dict)
                    hosts_created_count += 1
            logger.info("Hosts created in bulk")
            debounce_workspace_update(workspace_name)
            return make_response(jsonify(hosts_created=hosts_created_count,
                                         hosts_with_errors=hosts_with_errors_count), 200)
        except Exception as e:
            logger.error("Error parsing hosts CSV (%s)", e)
            abort(400, f"Error parsing hosts CSV ({e})")

    @route('/<host_id>/services')
    def service_list(self, workspace_name, host_id):
        """
        ---
        get:
          tags: ["Host", "Service"]
          summary: Get the services of a host
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: ServiceSchema
        tags: ["Host", "Service"]
        responses:
          200:
            description: Ok
        """
        services = self._get_object(host_id, workspace_name).services
        return ServiceSchema(many=True).dump(services)

    @route('/countVulns')
    def count_vulns(self, workspace_name):
        """
        ---
        get:
          tags: ["Host"]
          summary: Counts Vulnerabilities per host
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: HostCountSchema
        tags: ["Host"]
        responses:
          200:
            description: Ok
        """
        workspace = get_workspace(workspace_name)

        host_ids = flask.request.args.get('hosts', None)
        if host_ids:
            host_id_list = host_ids.split(',')
        else:
            host_id_list = None

        res_dict = {'hosts': {}}

        host_count_schema = HostCountSchema()
        host_count = Host.query_with_count(host_id_list, workspace)

        for host in host_count.all():
            res_dict["hosts"][host.id] = host_count_schema.dump(host)

        return res_dict

    @route('/<host_id>/tools_history')
    def tool_impacted_by_host(self, workspace_name, host_id):
        """
        ---
        get:
          tags: ["Host", "Command"]
          summary: "Get the command impacted by a host"
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: CommandSchema
        tags: ["Host", "Command"]
        responses:
          200:
            description: Ok
        """
        workspace = get_workspace(workspace_name)
        query = db.session.query(Host, Command).filter(Host.id == CommandObject.object_id,
                                                       CommandObject.object_type == 'host',
                                                       Command.id == CommandObject.command_id,
                                                       Host.workspace_id == workspace.id,
                                                       Host.id == host_id).order_by(desc(CommandObject.create_date))
        result = query.all()
        res_dict = {'tools': []}
        for row in result:
            _, command = row
            res_dict['tools'].append({'command': command.tool,
                                      'user': command.user,
                                      'params': command.params,
                                      'command_id': command.id,
                                      'create_date': command.create_date.replace(tzinfo=pytz.utc).isoformat()})
        return res_dict

    def _perform_create(self, data, **kwargs):
        hostnames = data.pop('hostnames', [])
        command_id = data.pop('command_id', None)
        host = super()._perform_create(data, **kwargs)
        for name in hostnames:
            get_or_create(db.session, Hostname, name=name, host=host,
                          workspace=host.workspace)
        if command_id:
            set_command_id(db.session, host, True, command_id)
        db.session.commit()
        if kwargs['workspace_name']:
            debounce_workspace_update(kwargs['workspace_name'])
        return host

    def _update_object(self, obj, data, **kwargs):
        try:
            hostnames = data.pop('hostnames')
        except KeyError:
            pass
        else:
            obj.set_hostnames(hostnames)

        # A commit is required here, otherwise it breaks (i'm not sure why)
        db.session.commit()

        return super()._update_object(obj, data)

    def _filter_query(self, query):
        query = super()._filter_query(query)
        search_term = flask.request.args.get('search', None)
        if search_term is not None:
            like_term = '%' + search_term + '%'
            match_ip = Host.ip.ilike(like_term)
            match_service_name = Host.services.any(
                Service.name.ilike(like_term))
            match_os = Host.os.ilike(like_term)
            match_hostname = Host.hostnames.any(Hostname.name.ilike(like_term))
            query = query.filter(match_ip
                                 | match_service_name
                                 | match_os
                                 | match_hostname)
        return query

    def patch(self, object_id, workspace_name=None, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        kwargs['exclude'] = ['severity_counts']
        if workspace_name:
            debounce_workspace_update(workspace_name)
        return super().patch(object_id, workspace_name=workspace_name, **kwargs)

    def _envelope_list(self, objects, pagination_metadata=None):
        hosts = []
        for index, host in enumerate(objects):
            # we use index when the filter endpoint uses group by and
            # the _id was not used in the group by
            hosts.append({
                'id': host.get('_id', index),
                'key': host.get('_id', index),
                'value': host
            })
        return {
            'rows': hosts,
            'count': (pagination_metadata and pagination_metadata.total or len(hosts)),
        }

    @route('', methods=['DELETE'])
    def bulk_delete(self, workspace_name, **kwargs):
        if workspace_name:
            debounce_workspace_update(workspace_name)
        # TODO REVISE ORIGINAL METHOD TO UPDATE NEW METHOD
        return BulkDeleteWorkspacedMixin.bulk_delete(self, workspace_name, **kwargs)

    bulk_delete.__doc__ = BulkDeleteWorkspacedMixin.bulk_delete.__doc__

    def _pre_bulk_update(self, data, **kwargs):
        hostnames = data.pop('hostnames', None)
        ans_data = super()._pre_bulk_update(data, **kwargs)
        if hostnames is not None:
            ans_data["hostnames"] = hostnames
        return ans_data

    def _post_bulk_update(self, ids, extracted_data, **kwargs):
        if "hostnames" in extracted_data:
            for obj in self._bulk_update_query(ids, **kwargs).all():
                obj.set_hostnames(extracted_data["hostnames"])
        if kwargs['workspace_name']:
            debounce_workspace_update(kwargs['workspace_name'])


HostsView.register(host_api)
