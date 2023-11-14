"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint
from filteralchemy import FilterSet, operators  # pylint:disable=unused-import
from marshmallow import fields
# Local application imports
from faraday.server.models import (
    Service
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
services_context_api = Blueprint('services_context_api', __name__)


class ServiceContextSchema(ServiceSchema):
    workspace_name = fields.String(attribute='workspace.name', dump_only=True)

    class Meta:
        model = Service
        fields = ('id', '_id', 'status', 'parent', 'type',
                  'protocol', 'description', '_rev',
                  'owned', 'owner', 'credentials', 'vulns',
                  'name', 'version', '_id', 'port', 'ports',
                  'metadata', 'summary', 'host_id', 'command_id', 'workspace_name')


class ServiceContextFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = Service
        fields = ('id', 'host_id', 'protocol', 'name', 'port', 'workspace_id')
        default_operator = operators.Equal
        operators = (operators.Equal,)


class ServiceContextView(PaginatedMixin, FilterMixin, FilterAlchemyMixin, ContextMixin, BulkDeleteMixin, BulkUpdateMixin):

    route_base = 'services'
    model_class = Service
    schema_class = ServiceContextSchema
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


ServiceContextView.register(services_context_api)
