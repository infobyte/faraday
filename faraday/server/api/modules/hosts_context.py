"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import logging

# Related third party imports
import pytz
import flask
from flask import Blueprint
from flask_classful import route
from sqlalchemy import desc
from sqlalchemy.orm import joinedload, undefer
# Local application imports
from faraday.server.utils.search import search
from faraday.server.api.base import (
    FilterMixin,
    PaginatedMixin,
    BulkDeleteMixin,
    BulkUpdateMixin,
    FilterSetMeta,
    FilterAlchemyMixin,
    ContextMixin
)
from faraday.server.api.modules.services import ServiceSchema

from faraday.server.models import Host, Workspace, Service, db, Hostname, CommandObject, Command
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.api.modules.hosts import HostSchema, HostCountSchema, HostFilterSet
host_context_api = Blueprint('host_context_api', __name__)
logger = logging.getLogger(__name__)


class HostContextFilterSet(HostFilterSet):
    class Meta(FilterSetMeta):
        model = Host
        fields = ('id', 'ip', 'name', 'os', 'service', 'port', 'workspace_id')


class HostsContextView(PaginatedMixin,
                       FilterAlchemyMixin,
                       ContextMixin,
                       FilterMixin,
                       BulkDeleteMixin,
                       BulkUpdateMixin):
    route_base = 'hosts'
    model_class = Host
    order_field = desc(Host.vulnerability_critical_generic_count), \
        desc(Host.vulnerability_high_generic_count), \
        desc(Host.vulnerability_medium_generic_count), \
        desc(Host.vulnerability_low_generic_count), \
        desc(Host.vulnerability_info_generic_count), \
        desc(Host.vulnerability_unclassified_generic_count), Host.ip.asc()

    schema_class = HostSchema
    filterset_class = HostContextFilterSet
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

    @route('/filter')
    def filter(self):
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
        filtered_objs, count = self._filter(filters, severity_count=True)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_objs, pagination_metadata)

    def _generate_filter_query(
            self, filters, severity_count=False, host_vulns=False, only_total_vulns=False, list_view=False
    ):
        filter_query = search(db.session,
                              self.model_class,
                              filters)

        if severity_count and 'group_by' not in filters:
            filter_query = filter_query.options(
                undefer(self.model_class.vulnerability_critical_generic_count),
                undefer(self.model_class.vulnerability_high_generic_count),
                undefer(self.model_class.vulnerability_medium_generic_count),
                undefer(self.model_class.vulnerability_low_generic_count),
                undefer(self.model_class.vulnerability_info_generic_count),
                undefer(self.model_class.vulnerability_unclassified_generic_count),
                undefer(self.model_class.credentials_count),
                undefer(self.model_class.open_service_count),
                joinedload(self.model_class.hostnames),
                joinedload(self.model_class.services),
                joinedload(self.model_class.update_user),
                joinedload(getattr(self.model_class, 'creator')).load_only('username'),
            )
        filter_query = (self._apply_filter_context(filter_query).
                        filter(Host.workspace.has(active=True)))  # only hosts from active workspaces
        return filter_query

    @route('/<host_id>/services')
    def service_list(self, host_id):
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
        services = self._get_object(host_id).services
        return ServiceSchema(many=True).dump(services)

    @route('/countVulns')
    def count_vulns(self):
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

        host_ids = flask.request.args.get('hosts', None)
        if host_ids:
            host_id_list = host_ids.split(',')
        else:
            host_id_list = None

        res_dict = {'hosts': {}}

        host_count_schema = HostCountSchema()
        for workspace in self._get_context_workspace_query().all():
            host_count = Host.query_with_count(host_id_list, workspace)

            for host in host_count.all():
                res_dict["hosts"][host.id] = host_count_schema.dump(host)

        return res_dict

    @route('/<host_id>/tools_history')
    def tool_impacted_by_host(self, host_id):
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
        query = db.session.query(Host, Command).filter(Host.id == CommandObject.object_id,
                                                       CommandObject.object_type == 'host',
                                                       Command.id == CommandObject.command_id,
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
        workspaces = Workspace.query.join(Host).filter(Host.id.in_(ids)).distinct(Workspace.name).all()
        for workspace in workspaces:
            debounce_workspace_update(workspace.name)

    def _perform_bulk_delete(self, values, **kwargs):
        workspaces = Workspace.query.join(Host).filter(Host.id.in_(values)).distinct(Workspace.name).all()
        response = super()._perform_bulk_delete(values, **kwargs)
        for workspace in workspaces:
            debounce_workspace_update(workspace.name)
        return response


HostsContextView.register(host_context_api)
