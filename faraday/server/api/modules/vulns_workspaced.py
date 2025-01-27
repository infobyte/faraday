"""
Faraday Penetration Test IDE
Copyright (C) 2024  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
from http.client import BAD_REQUEST as HTTP_BAD_REQUEST
from logging import getLogger

# Related third party imports
from flask import Blueprint, abort, request
from sqlalchemy.orm import joinedload, selectin_polymorphic, undefer, noload

# Local application imports
from faraday.server.api.base import (
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    ReadWriteWorkspacedView,
    get_workspace,
)
from faraday.server.api.modules.vulns_base import VulnerabilityFilterSet, VulnerabilityView
from faraday.server.config import faraday_server
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.models import (
    Host,
    Service,
    Vulnerability,
    VulnerabilityGeneric,
    VulnerabilityWeb,
    db,
)
from faraday.server.utils.command import set_command_id
from faraday.server.utils.cwe import create_cwe
from faraday.server.utils.reference import create_reference
from faraday.server.utils.vulns import (
    WORKSPACED_SCHEMA_EXCLUDE_FIELDS,
    parse_cve_references_and_policyviolations,
    update_one_host_severity_stat,
)

vulns_workspaced_api = Blueprint('vulns_workspaced_api', __name__)
logger = getLogger(__name__)


class VulnerabilityWorkspacedFilterSet(VulnerabilityFilterSet):
    class Meta(VulnerabilityFilterSet.Meta):
        base_fields = VulnerabilityFilterSet.Meta.fields
        fields = tuple(field for field in base_fields if field not in WORKSPACED_SCHEMA_EXCLUDE_FIELDS)


class VulnerabilityWorkspacedView(
    ReadWriteWorkspacedView,
    BulkDeleteWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    VulnerabilityView,
):
    filterset_class = VulnerabilityWorkspacedFilterSet

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

            joinedload('refs'),
            joinedload('cve_instances'),
            joinedload('policy_violation_instances'),
        ]

        if request.args.get('get_evidence'):
            options.append(joinedload(VulnerabilityGeneric.evidence))
        else:
            options.append(noload(VulnerabilityGeneric.evidence))

        return query.options(selectin_polymorphic(
            VulnerabilityGeneric,
            [Vulnerability, VulnerabilityWeb]
        ), *options)

    def _bulk_update_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        query = self.model_class.query.filter(self.model_class.id.in_(ids))
        workspace = get_workspace(kwargs.pop("workspace_name"))
        return query.filter(self.model_class.workspace_id == workspace.id)

    def _bulk_delete_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        if kwargs.get("by", "id") != "severity":
            query = self.model_class.query.filter(self.model_class.id.in_(ids))
        else:
            query = self.model_class.query.filter(self.model_class.severity.in_(ids))
        workspace = get_workspace(kwargs.pop("workspace_name"))
        return query.filter(self.model_class.workspace_id == workspace.id)

    def _perform_delete(self, obj, **kwargs):
        # Update hosts stats
        host_to_update_stat = None
        if obj.host_id:
            host_to_update_stat = obj.host_id
        elif obj.service_id:
            host_to_update_stat = obj.service.host_id

        db.session.delete(obj)
        db.session.commit()
        logger.info(f"{obj} deleted")

        if kwargs['workspace_name']:
            debounce_workspace_update(kwargs['workspace_name'])

        if host_to_update_stat:
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel

            if faraday_server.celery_enabled:
                update_host_stats.delay([host_to_update_stat], [])
            else:
                update_host_stats([host_to_update_stat], [])
        db.session.commit()

    def _perform_create(self, data, **kwargs):
        data = self._parse_data(self._get_schema_instance(kwargs), request)
        obj = None
        # TODO migration: use default values when popping and validate the
        # popped object has the expected type.
        # This will be set after setting the workspace
        attachments = data.pop('_attachments', {})
        references = data.pop('refs', [])
        policyviolations = data.pop('policy_violations', [])
        cve_list = data.pop('cve', [])
        cwe_list = data.pop('cwe', [])
        command_id = data.pop('command_id', None)

        try:
            obj = super()._perform_create(data, **kwargs)
        except TypeError:
            # TypeError is raised when trying to instantiate a sqlalchemy model
            # with invalid attributes, for example VulnerabilityWeb with host_id
            abort(HTTP_BAD_REQUEST)

        obj = parse_cve_references_and_policyviolations(obj, references, policyviolations, cve_list)
        obj.cwe = create_cwe(cwe_list)

        db.session.flush()
        if command_id:
            set_command_id(db.session, obj, True, command_id)
        self._process_attachments(obj, attachments)
        if not obj.tool:
            if obj.creator_command_tool:
                obj.tool = obj.creator_command_tool
            else:
                obj.tool = "Web UI"
        db.session.commit()

        # Update hosts stats
        host_to_update_stat = None
        if obj.host_id:
            host_to_update_stat = obj.host_id
        elif obj.service_id:
            host_to_update_stat = obj.service.host_id

        if kwargs['workspace_name']:
            debounce_workspace_update(kwargs['workspace_name'])

        if host_to_update_stat:
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel
            if faraday_server.celery_enabled:
                update_host_stats.delay([host_to_update_stat], [])
            else:
                update_host_stats([host_to_update_stat], [])

        return obj

    def _update_object(self, obj, data, **kwargs):
        data.pop('type', '')  # It's forbidden to change vuln type!
        data.pop('tool', '')

        cwe_list = data.pop('cwe', None)
        if cwe_list:
            # We need to instantiate cwe objects before updating
            obj.cwe = create_cwe(cwe_list)

        reference_list = data.pop('refs', None)
        if reference_list is not None:
            # We need to instantiate reference objects before updating
            obj.refs = create_reference(reference_list, vulnerability_id=obj.id)

        # These fields (cvss2, cvss3 and cvss4) are better to be processed in this way because the model parse
        # vector string into fields and calculates the scores
        if 'cvss2_vector_string' in data:
            obj.cvss2_vector_string = data.pop('cvss2_vector_string')

        if 'cvss3_vector_string' in data:
            obj.cvss3_vector_string = data.pop('cvss3_vector_string')

        if 'cvss4_vector_string' in data:
            obj.cvss4_vector_string = data.pop('cvss4_vector_string')

        return super()._update_object(obj, data)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False, **kwargs):
        attachments = data.pop('_attachments', None if partial else {})

        # get hosts and services to update vuln stats
        hosts, services = update_one_host_severity_stat(obj)

        obj = super()._perform_update(object_id, obj, data, workspace_name)
        db.session.flush()

        if attachments is not None:
            self._process_attachments(obj, attachments)

        db.session.commit()

        if workspace_name:
            debounce_workspace_update(workspace_name)

        if hosts or services:
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel
            if faraday_server.celery_enabled:
                update_host_stats.delay(hosts, services)
            else:
                update_host_stats(hosts, services)

        return obj

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

    def put(self, object_id, workspace_name=None, **kwargs):
        """
                ---
                  tags: ["Vulnerability"]
                  summary: Updates Vulnerability
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
                        schema: VulnerabilitySchema
                  responses:
                    200:
                      description: Ok
                      content:
                        application/json:
                          schema: VulnerabilitySchema
                """
        if workspace_name:
            debounce_workspace_update(workspace_name)
        return super().put(object_id, workspace_name=workspace_name, eagerload=True, **kwargs)


VulnerabilityWorkspacedView.register(vulns_workspaced_api)
