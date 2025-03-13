"""
Faraday Penetration Test IDE
Copyright (C) 2024  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
from csv import DictReader
from http.client import BAD_REQUEST as HTTP_BAD_REQUEST, FORBIDDEN as HTTP_FORBIDDEN, OK as HTTP_OK
from io import StringIO
from logging import getLogger
from re import findall

# Related third party imports
from flask import Blueprint, abort, jsonify, make_response, request
from flask_classful import route
from flask_wtf.csrf import validate_csrf
from wtforms import ValidationError

# Local application imports
from faraday.server.api.base import (
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    FilterWorkspacedMixin,
    ReadWriteWorkspacedView,
    get_workspace,
)
from faraday.server.api.modules.hosts_base import HostFilterSet, HostView
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.models import Host, Hostname, Service, db
from faraday.server.utils.command import set_command_id
from faraday.server.utils.database import get_or_create
from faraday.server.utils.hosts import WORKSPACED_SCHEMA_EXCLUDE_FIELDS

host_workspaced_api = Blueprint('host_workspaced_api', __name__)
logger = getLogger(__name__)


class HostWorkspacedFilterSet(HostFilterSet):
    class Meta(HostFilterSet.Meta):
        base_fields = HostFilterSet.Meta.fields
        fields = tuple(field for field in base_fields if field not in WORKSPACED_SCHEMA_EXCLUDE_FIELDS)


class HostWorkspacedView(
    FilterWorkspacedMixin,
    ReadWriteWorkspacedView,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    HostView,
):
    filterset_class = HostWorkspacedFilterSet

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
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
            abort(HTTP_FORBIDDEN)

        def parse_hosts(list_string):
            items = findall(r"([.a-zA-Z0-9_-]+)", list_string)
            return items

        workspace = get_workspace(workspace_name)

        logger.info("Create hosts from CSV")
        if 'file' not in request.files:
            abort(HTTP_BAD_REQUEST, "Missing File in request")
        hosts_file = request.files['file']
        stream = StringIO(hosts_file.stream.read().decode("utf-8"), newline=None)
        FILE_HEADERS = {'description', 'hostnames', 'ip', 'os'}
        try:
            hosts_reader = DictReader(stream)
            if set(hosts_reader.fieldnames) != FILE_HEADERS:
                logger.error("Missing Required headers in CSV (%s)", FILE_HEADERS)
                abort(HTTP_BAD_REQUEST, f"Missing Required headers in CSV ({FILE_HEADERS})")
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
                                         hosts_with_errors=hosts_with_errors_count), HTTP_OK)
        except Exception as e:
            logger.error("Error parsing hosts CSV (%s)", e)
            abort(HTTP_BAD_REQUEST, f"Error parsing hosts CSV ({e})")

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

        # A commit is required here, otherwise it breaks (I'm not sure why)
        db.session.commit()

        return super()._update_object(obj, data)

    def _filter_query(self, query):
        query = super()._filter_query(query)
        search_term = request.args.get('search', None)
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


HostWorkspacedView.register(host_workspaced_api)
