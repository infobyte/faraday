"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint
from filteralchemy import FilterSet, operators  # pylint:disable=unused-import
# Local application imports
from faraday.server.models import (
    Service,
    db,
    Workspace
)
from faraday.server.api.base import (
    FilterMixin,
    ContextMixin,
    BulkDeleteMixin,
    BulkUpdateMixin,
    FilterSetMeta,
    FilterAlchemyMixin,
    PaginatedMixin
)
from faraday.server.api.modules.services import ServiceSchema
from faraday.server.utils.search import search
from faraday.server.debouncer import debounce_workspace_update

services_context_api = Blueprint('services_context_api', __name__)


class ServiceContextFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Service
        fields = ('id', 'host_id', 'protocol', 'name', 'port', 'workspace_id')
        default_operator = operators.Equal
        operators = (operators.Equal,)


class ServiceContextView(PaginatedMixin, FilterMixin, FilterAlchemyMixin, ContextMixin, BulkDeleteMixin, BulkUpdateMixin):

    route_base = 'services'
    model_class = Service
    schema_class = ServiceSchema
    count_extra_filters = [Service.status == 'open']
    get_undefer = [Service.credentials_count, Service.vulnerability_count]
    get_joinedloads = [Service.credentials, Service.update_user]
    filterset_class = ServiceContextFilterSet

    def _envelope_list(self, objects, pagination_metadata=None):
        services = []
        for service in objects:
            services.append({
                'id': service['_id'],
                'key': service['_id'],
                'value': service
            })
        return {
            'services': services,
            'count': (pagination_metadata.total
                      if pagination_metadata is not None else len(services))
        }

    def _generate_filter_query(
            self, filters, severity_count=False, host_vulns=False, only_total_vulns=False, list_view=False
    ):
        filter_query = search(db.session,
                              self.model_class,
                              filters)

        filter_query = (self._apply_filter_context(filter_query).
                        filter(Service.workspace.has(active=True)))  # only services from active workspaces
        return filter_query

    def _perform_bulk_delete(self, values, **kwargs):
        workspaces = Workspace.query.join(Service).filter(Service.id.in_(values)).distinct(Workspace.name).all()
        response = super()._perform_bulk_delete(values, **kwargs)
        for workspace in workspaces:
            debounce_workspace_update(workspace.name)
        return response


ServiceContextView.register(services_context_api)
