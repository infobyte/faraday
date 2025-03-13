"""
Faraday Penetration Test IDE
Copyright (C) 2024  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
from http.client import BAD_REQUEST as HTTP_BAD_REQUEST

# Related third party imports
from flask import Blueprint, abort, jsonify, make_response

# Local application imports
from faraday.server.api.base import (
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    FilterWorkspacedMixin,
    ReadWriteWorkspacedView,
)
from faraday.server.api.modules.services_base import ServiceFilterSet, ServiceView
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.models import db
from faraday.server.utils.command import set_command_id
from faraday.server.utils.services import WORKSPACED_SCHEMA_EXCLUDE_FIELDS

services_workspaced_api = Blueprint('services_workspaced_api', __name__)


class ServiceWorkspacedFilterSet(ServiceFilterSet):
    class Meta(ServiceFilterSet.Meta):
        base_fields = ServiceFilterSet.Meta.fields
        fields = tuple(field for field in base_fields if field not in WORKSPACED_SCHEMA_EXCLUDE_FIELDS)


class ServiceWorkspacedView(
    ReadWriteWorkspacedView,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    FilterWorkspacedMixin,
    ServiceView,
):

    filterset_class = ServiceWorkspacedFilterSet

    def _perform_create(self, data, workspace_name):
        command_id = data.pop('command_id', None)
        port_number = data.get("port", "1")

        if not port_number.isdigit():
            abort(make_response(jsonify(message="Invalid Port number"), HTTP_BAD_REQUEST))

        service = super()._perform_create(data, workspace_name)

        if command_id:
            set_command_id(db.session, service, True, command_id)

        debounce_workspace_update(workspace_name)

        return service

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False):
        service = super()._perform_update(object_id, obj, data, workspace_name=workspace_name, partial=partial)
        debounce_workspace_update(workspace_name)
        return service


ServiceWorkspacedView.register(services_workspaced_api)
