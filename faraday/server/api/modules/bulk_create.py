# Standard library imports
import logging
import re
import string
import random
import json
from copy import deepcopy
import time
from datetime import datetime, timedelta, date
from typing import Type

# Related third party imports
import flask_login
import flask
import sqlalchemy
import cvss

from flask import abort
from sqlalchemy import func, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm.exc import NoResultFound
from marshmallow import (
    Schema,
    ValidationError,
    validates_schema,
    fields,
    post_load,
    utils,
)
from marshmallow.validate import Range

# Local application imports
from faraday.server.utils.cvss import (
    get_base_score,
    get_severity,
    get_temporal_score,
    get_environmental_score,
    get_propper_value,
    get_exploitability_score,
    get_impact_score
)
from faraday.server.models import (
    db,
    Command,
    CommandObject,
    Credential,
    Host,
    Hostname,
    Service,
    Vulnerability,
    AgentExecution,
    Workspace,
    Metadata,
    CVE,
    VulnerabilityReference,
    owasp_vulnerability_association,
    cwe_vulnerability_association,
    PolicyViolationVulnerabilityAssociation,
    SeveritiesHistogram,
    cve_vulnerability_association,
)
from faraday.server.utils.cwe import get_or_create_cwe
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation,
    get_object_type_for,
)
from faraday.server.api.base import (
    AutoSchema,
    GenericWorkspacedView,
    get_workspace
)
from faraday.server.api.modules import (
    hosts,
    services,
    vulns,
)
from faraday.server.api.modules.websocket_auth import require_agent_token
from faraday.server.utils.vulns import (
    get_or_create_owasp,
    create_cve_obj,
    create_policy_violation_obj
)
from faraday.server.config import CONST_FARADAY_HOME_PATH
from faraday.server.config import faraday_server
from faraday.server.tasks import process_report_task

bulk_create_api = flask.Blueprint('bulk_create_api', __name__)
logger = logging.getLogger(__name__)


class VulnerabilitySchema(vulns.VulnerabilitySchema):
    class Meta(vulns.VulnerabilitySchema.Meta):
        extra_fields = ('run_date',)
        fields = tuple(
            field_name for field_name in (vulns.VulnerabilitySchema.Meta.fields + extra_fields)
            if field_name not in ('parent', 'parent_type')
        )


class BulkVulnerabilityWebSchema(vulns.VulnerabilityWebSchema):
    class Meta(vulns.VulnerabilityWebSchema.Meta):
        extra_fields = ('run_date',)
        fields = tuple(
            field_name for field_name in (vulns.VulnerabilityWebSchema.Meta.fields + extra_fields)
            if field_name not in ('parent', 'parent_type')
        )


class PolymorphicVulnerabilityField(fields.Field):
    """Used like a nested field with many objects, but it decides which
    schema to use based on the type of each vuln"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.many = kwargs.get('many', False)
        self.vuln_schema = VulnerabilitySchema()
        self.vulnweb_schema = BulkVulnerabilityWebSchema()

    def _deserialize(self, value, attr, data, **kwargs):
        if self.many and not utils.is_collection(value):
            self.fail('type', input=value, type=value.__class__.__name__)
        if self.many:
            return [self._deserialize_item(item) for item in value]
        return self._deserialize_item(value)

    def _deserialize_item(self, value):
        try:
            type_ = value.get('type')
        except AttributeError as e:
            raise ValidationError("Value is expected to be an object") from e
        if type_ == 'Vulnerability':
            schema = self.vuln_schema
        elif type_ == 'VulnerabilityWeb':
            schema = self.vulnweb_schema
        else:
            raise ValidationError('type must be "Vulnerability" or "VulnerabilityWeb"')
        return schema.load(value)


class BulkCredentialSchema(AutoSchema):
    class Meta:
        model = Credential
        fields = ('username', 'password', 'description', 'name')


class BulkServiceSchema(services.ServiceSchema):
    """It's like the original service schema, but now it only uses port
    instead of ports (a single integer array). That field was only used
    to keep backwards compatibility with the Web UI"""
    port = fields.Integer(required=True,
                          validate=[Range(min=0, error="The value must be greater than or equal to 0")])
    vulnerabilities = PolymorphicVulnerabilityField(
        many=True,
        missing=[],
    )
    credentials = fields.Nested(
        BulkCredentialSchema(many=True),
        many=True,
        missing=[],
    )

    def post_load_parent(self, data, **kwargs):
        # Don't require the parent field
        return

    class Meta(services.ServiceSchema.Meta):
        fields = tuple(
            field_name for field_name in services.ServiceSchema.Meta.fields
            if field_name not in ('parent', 'ports')
        ) + ('vulnerabilities',)


class HostBulkSchema(hosts.HostSchema):
    ip = fields.String(required=True)
    services = fields.Nested(
        BulkServiceSchema(many=True, context={'updating': False}),
        many=True,
        missing=[],
    )
    vulnerabilities = fields.Nested(
        VulnerabilitySchema(many=True),
        many=True,
        missing=[],
    )
    credentials = fields.Nested(
        BulkCredentialSchema(many=True),
        many=True,
        missing=[],
    )

    class Meta(hosts.HostSchema.Meta):
        fields = hosts.HostSchema.Meta.fields + ('services', 'vulnerabilities')

    @validates_schema
    def validate_schema(self, data, **kwargs):
        for vulnerability in data['vulnerabilities']:
            if vulnerability['type'] != 'vulnerability':
                raise ValidationError('Type "Vulnerability Web" cannot have "Host" type as a parent')


class BulkCommandSchema(AutoSchema):
    """The schema of faraday/server/api/modules/commandsrun.py has a lot
    of ugly things because of the Web UI backwards compatibility.

    I don't need that here, so I'll write a schema from scratch."""

    duration = fields.TimeDelta('microseconds', required=False)

    class Meta:
        model = Command
        fields = (
            'command', 'duration', 'start_date', 'ip', 'hostname', 'params',
            'user', 'creator', 'tool', 'import_source',
        )

    @post_load
    def load_end_date(self, data, **kwargs):
        if 'duration' in data:
            duration = data.pop('duration')
            data['end_date'] = data['start_date'] + duration
        return data


class BulkCreateSchema(Schema):
    hosts = fields.Nested(
        HostBulkSchema(many=True),
        many=True,
        required=True,
    )
    command = fields.Nested(
        BulkCommandSchema(),
        required=True,
    )
    execution_id = fields.Integer(attribute='execution_id')


def get_or_create(ws: Workspace, model_class: Type[Metadata], data: dict):
    """Check for conflicts and create a new object

    Is is passed the data parsed by the marshmallow schema (it
    transform from raw post data to a JSON)
    """
    nested = db.session.begin_nested()
    try:
        obj = model_class(**data)
        obj.workspace = ws
        db.session.add(obj)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError as ex:
        if not is_unique_constraint_violation(ex):
            raise
        nested.rollback()
        conflict_obj = get_conflict_object(db.session, obj, data, ws)
        if conflict_obj:
            return False, conflict_obj
        else:
            raise
    return True, obj


def bulk_create(ws: Workspace,
                command: [Command],
                data: dict,
                data_already_deserialized: bool = False,
                set_end_date: bool = True):

    logger.info("Init bulk create process")

    if data_already_deserialized is False:
        schema = BulkCreateSchema()
        data = schema.load(data)

    _update_command(command.id, data['command'])

    command_dict = {'id': command.id, 'tool': command.tool, 'user': command.user}
    workspace_id = ws.id

    hosts_to_create = len(data['hosts'])
    if hosts_to_create > 0:
        logger.debug(f"Needs to create {hosts_to_create} hosts...")

        if faraday_server.celery_enabled:
            # This will fix redis broken pipe
            # loops = ceil(len(all_hosts) / 100)
            # tasks = []
            # from_host = 0
            # to_host = 0
            # for loop in range(loops):
            #     to_host += 300
            #     task = process_report_task.delay(workspace_id, command_dict, all_hosts[from_host:to_host])
            #     from_host = loop * 300
            #     tasks.append(task)
            # return tasks
            return process_report_task.delay(workspace_id, command_dict, data['hosts'])

        # just in case celery is not configured
        for host in data['hosts']:
            _create_host(ws, host, command_dict)
    else:
        logger.info("No hosts to create")

    # TODO: Add this in professional
    if 'command' in data and set_end_date:
        command.end_date = datetime.utcnow() if command.end_date is None else command.end_date
        db.session.commit()


def _update_command(command_id: int, command_data: dict):
    command = db.session.query(Command).filter(Command.id == command_id)
    command.update(command_data)
    db.session.commit()
    return command


def get_created_tuple(obj: object) -> tuple:
    return deepcopy(obj.__class__.__name__), deepcopy(obj.id), deepcopy(obj.workspace.id)


def _create_host(ws, host_data, command: dict):
    logger.debug("Trying to create host...")
    start_time = time.time()
    hostnames = host_data.pop('hostnames', [])
    _services = host_data.pop('services', [])
    credentials = host_data.pop('credentials', [])
    _vulns = host_data.pop('vulnerabilities', [])

    created_updated_count = {'created': 0, 'updated': 0, 'host_id': None}

    try:
        created, host = get_or_create(ws, Host, host_data)
        created_updated_count['host_id'] = host.id
    except Exception as e:
        logger.exception("Could not create host %s", host_data['ip'], exc_info=e)

    for name in set(hostnames).difference(set(map(lambda x: x.name, host.hostnames))):
        db.session.add(Hostname(name=name, host=host, workspace=ws))
    db.session.commit()

    # if command is not None // white?
    _create_command_object_for(ws, created, host, command)
    total_services = len(_services)
    if total_services > 0:
        logger.debug(f"Needs to create {total_services} services...")
        for service_data in _services:
            _result = _create_service(ws, host, service_data, command)
            created_updated_count['created'] += _result['created']
            created_updated_count['updated'] += _result['updated']

    start_time_vulns = time.time()
    total_vulns = len(_vulns)
    host_vulns_created = []
    if total_vulns > 0:
        logger.debug(f"Needs to create {total_vulns} vulns...")
        processed_data = {}
        for vuln_data in _vulns:
            logger.debug("Creating vulnerability ")
            logger.debug(vuln_data)
            host_vuln_dict, vuln_id = _create_hostvuln(ws, host, vuln_data, command)

            updated_processed_data = host_vuln_dict.get(vuln_id, None)
            if not updated_processed_data:
                logger.error(f"Vuln data for {vuln_id} not found")
            logger.debug("UPDATED PROC DATA")
            logger.debug(updated_processed_data)
            processed_data.update(host_vuln_dict)

            updated_vuln_data = updated_processed_data.get('vuln_data', None)
            if not updated_vuln_data:
                logger.error(f"Vuln data for {vuln_id} not found")
            logger.debug("UPDATED VULN DATA")
            logger.debug(updated_vuln_data)
            host_vulns_created.append(updated_vuln_data)

        _result = insert_vulnerabilities(host_vulns_created, processed_data, workspace_id=ws.id)
        created_updated_count['created'] += _result['created']
        created_updated_count['updated'] += _result['updated']

    logger.debug(f"Host vulnerabilities creation took {time.time() - start_time_vulns}."
                 f" Created: {created_updated_count['created']}."
                 f" Updated: {created_updated_count['updated']}"
                 )

    total_credentials = len(credentials)
    if total_credentials > 0:
        logger.debug(f"Needs to create {total_credentials} credentials...")
        for cred_data in credentials:
            _create_credential(ws, cred_data, command, host=host)
    logger.debug(f"Create host took {time.time() - start_time}")

    return created_updated_count


def insert_vulnerabilities(host_vulns_created, processed_data, workspace_id=None):
    stmt = insert(Vulnerability).values(host_vulns_created)
    on_update_stmt = stmt.on_conflict_do_update(
        index_elements=[func.md5(text('name')),
                        func.md5(text('description')),
                        text('type'),
                        func.COALESCE(text('host_id'), -1),
                        func.COALESCE(text('service_id'), -1),
                        func.COALESCE(func.md5(text('method')), ''),
                        func.COALESCE(func.md5(text('parameter_name')), ''),
                        func.COALESCE(func.md5(text('path')), ''),
                        func.COALESCE(func.md5(text('website')), ''),
                        text('workspace_id'),
                        func.COALESCE(text('source_code_id'), -1)
                        ],
        set_={
            "_tmp_id": stmt.excluded.id,
            "status": "re-opened",
            "custom_fields": stmt.excluded.custom_fields
        },
        where=(Vulnerability.status == 'closed')
    ).returning(text('id'), text('_tmp_id'))
    result = db.session.execute(on_update_stmt)
    db.session.commit()
    total_result = manage_relationships(
        processed_data,
        result,
        workspace_id=workspace_id
    )
    return total_result


def set_histogram(histogram, vuln_data):
    severity = vuln_data['severity']
    confirmed = vuln_data['confirmed']

    logger.debug("Setting histogram severity %s %s", severity, confirmed)
    histogram['critical'] += 1 if severity == 'critical' else 0
    histogram['high'] += 1 if severity == 'high' else 0
    histogram['medium'] += 1 if severity == 'medium' else 0
    histogram['confirmed'] += 1 if confirmed else 0


def _create_or_update_histogram(histogram: dict = None) -> None:
    logger.debug("Creating histogram into database %s", histogram)
    if histogram is None:
        logger.error("Workspace with None value. Histogram could not be updated")
        return
    stmt = insert(SeveritiesHistogram).values(histogram)
    on_update_stmt = stmt.on_conflict_do_update(
        index_elements=[text('date'), text('workspace_id')],
        set_={
            "critical": text("severities_histogram.critical") + stmt.excluded.critical,
            "high": text("severities_histogram.high") + stmt.excluded.high,
            "medium": text("severities_histogram.medium") + stmt.excluded.medium,
            "confirmed": text("severities_histogram.confirmed") + stmt.excluded.confirmed
        }
    )
    db.session.execute(on_update_stmt)


def manage_relationships(processed_data, result, workspace_id=None):
    references_created = []
    command_objects_created = []
    cve_association_created = []
    owasp_object_created = []
    cwe_object_created = []
    policy_object_created = []
    created = 0
    updated = 0

    if not workspace_id:
        logger.error('Workspace id not provided')
        return

    histogram = {'workspace_id': workspace_id, 'date': date.today(), 'high': 0, 'critical': 0, 'medium': 0, 'confirmed': 0}

    for r in result:
        if r[1]:
            v_id = r[0]
            data = processed_data.get(r[1], None)
            logger.debug(f"Found conflict {r[0]}/{r[1]}")
            # Delete from lists
            logger.debug("Data On conflic %s", data)
            if data['references']:
                for reference in data['references']:
                    reference_sequence_id = db.session.execute(
                        "SELECT nextval('vulnerability_reference_id_seq');").scalar()
                    logger.debug(f"Found reference {reference} for vulnerability {v_id}")
                    reference['id'] = reference_sequence_id
                    reference['vulnerability_id'] = v_id
                    references_created.append(reference)
            logger.debug("Data vulnerability On conflic %s", data['vuln_data'])
            updated += 1
            set_histogram(histogram, data['vuln_data'])
        else:
            created += 1
            v_id = r[0]
            data = processed_data.get(v_id, None)
            set_histogram(histogram, data['vuln_data'])
            logger.debug(f"{data.keys()} all data *************")
            logger.debug(f"{data['vuln_data'].keys()} all data *************")
            if data['cve_associations']:
                for cve_association in data['cve_associations']:
                    logger.debug(f"Found cve_association {cve_association} for vulnerability {r[0]}")
                    cve_association_created.append(cve_association)
            logger.debug(f"Processing references for {v_id}")
            if data['references']:
                for reference in data['references']:
                    reference_sequence_id = db.session.execute(
                        "SELECT nextval('vulnerability_reference_id_seq');").scalar()
                    logger.debug(f"Found reference {reference} for vulnerability {r[0]}")
                    reference['id'] = reference_sequence_id
                    references_created.append(reference)
            logger.debug(f"Processing command for {v_id}")
            if data['command']:
                command_object_sequence_id = db.session.execute(
                    "SELECT nextval('command_object_id_seq');").scalar()
                data['command']['id'] = command_object_sequence_id
                command_objects_created.append(data['command'])
            for owasp_object in data['owasp_objects']:
                owasp_object_created.append(owasp_object)
            for cwe_association in data['cwe_associations']:
                cwe_object_created.append(cwe_association)
            for policy in data['policy_violations_associations']:
                policy_object_created.append(policy)
    # TODO: Improve with an iterator
    if references_created:
        stmt = insert(VulnerabilityReference).values(references_created).on_conflict_do_nothing()
        db.session.execute(stmt)
    if cve_association_created:
        stmt = cve_vulnerability_association.insert().values(cve_association_created)
        db.session.execute(stmt)
    if command_objects_created:
        stmt = insert(CommandObject).values(command_objects_created).on_conflict_do_nothing()
        db.session.execute(stmt)
    if owasp_object_created:
        stmt = insert(owasp_vulnerability_association).values(owasp_object_created).on_conflict_do_nothing()
        db.session.execute(stmt)
    if cwe_object_created:
        stmt = insert(cwe_vulnerability_association).values(cwe_object_created).on_conflict_do_nothing()
        db.session.execute(stmt)
    if policy_object_created:
        stmt = insert(PolicyViolationVulnerabilityAssociation).values(policy_object_created).on_conflict_do_nothing()
        db.session.execute(stmt)
    _create_or_update_histogram(histogram)
    db.session.commit()

    return {'created': created, 'updated': updated}


def _create_command_object_for(ws, created, obj, command: dict):
    assert command is not None
    data = {
        'object_id': obj.id,
        'object_type': get_object_type_for(obj),
        'command_id': command['id'],
        'created_persistent': created,
        'workspace': ws,
    }
    get_or_create(ws, CommandObject, data)
    db.session.commit()


def _create_command_json(ws_id: int, obj_id: int, command: dict) -> dict:
    assert command is not None
    data = {
        'object_id': obj_id,
        'object_type': 'vulnerability',
        'command_id': command['id'],
        'created_persistent': True,  # TODO: are we using this?
        'workspace_id': ws_id,
    }
    return data


def _update_service(service: Service, service_data: dict) -> Service:
    keys = ['version', 'description', 'name', 'status', 'owned']
    updated = False

    for key in keys:
        if key == 'owned':
            value = service_data.get(key, False)
        else:
            value = service_data.get(key, '')
        if value != getattr(service, key):
            setattr(service, key, value)
            updated = True

    if updated:
        service.update_date = datetime.utcnow()

    return service


def _create_service(ws, host, service_data, command: dict):
    service_data = service_data.copy()
    _vulns = service_data.pop('vulnerabilities', [])
    creds = service_data.pop('credentials', [])
    service_data['host'] = host
    created_updated_count = {'created': 0, 'updated': 0}

    created, service = get_or_create(ws, Service, service_data)

    if not created:
        service = _update_service(service, service_data)

    _create_command_object_for(ws, created, service, command)

    start_time_vulns = time.time()
    total_service_vulns = len(_vulns)
    host_vulns_created = []
    if total_service_vulns > 0:
        logger.debug(f"Needs to create {total_service_vulns} service vulns...")
        processed_data = {}
        for vuln_data in _vulns:
            logger.debug("Creating vulnerability ")
            logger.debug(vuln_data)
            host_vuln_dict, vuln_id = _create_servicevuln(ws, service, vuln_data, command)

            updated_processed_data = host_vuln_dict.get(vuln_id, None)
            if not updated_processed_data:
                logger.error(f"Vuln data for {vuln_id} not found")
            logger.debug("UPDATED PROC DATA")
            logger.debug(updated_processed_data)
            processed_data.update(host_vuln_dict)

            updated_vuln_data = updated_processed_data.get('vuln_data', None)
            if not updated_vuln_data:
                logger.error(f"Vuln data for {vuln_id} not found")
            logger.debug("UPDATED VULN DATA")
            logger.debug(updated_vuln_data)
            host_vulns_created.append(updated_vuln_data)

        created_updated_count = insert_vulnerabilities(host_vulns_created, processed_data, workspace_id=ws.id)

    logger.debug(f"Service vulnerabilities creation took {time.time() - start_time_vulns}")

    total_service_creds = len(creds)
    if total_service_creds > 0:
        logger.debug(f"Needs to create {total_service_creds} service credentials...")
        for cred_data in creds:
            _create_credential(ws, cred_data, command, service=service)

    return created_updated_count


def validate_vuln_type(vulnerability):
    if vulnerability['type'] not in ['vulnerability', 'Vulnerability', 'VulnerabilityWeb', 'vulnerability_web']:
        raise ValidationError("unknown type")

    if 'host' in vulnerability and vulnerability['type'] not in ['vulnerability', 'Vulnerability']:
        raise ValidationError('Type must be "Vulnerability"')

    return True


def get_run_date(run_date_string):
    run_date = None
    if run_date_string:
        try:
            run_timestamp = float(run_date_string)
            run_date = datetime.utcfromtimestamp(run_timestamp)
            if (datetime.utcnow() + timedelta(hours=24)) < run_date:
                run_date = None
                logger.debug("Run date (%s) is greater than allowed", run_date)
        except ValueError:
            logger.error("Error converting [%s] to a valid date", run_date_string)
            raise
    return run_date


def _create_vuln(ws, vuln_data, command: dict, **kwargs):
    """Create standard or web vulnerabilities"""
    assert 'host' in kwargs or 'service' in kwargs
    assert not ('host' in kwargs and 'service' in kwargs)

    vuln_data = vuln_data.copy()
    vuln_data.update(kwargs)

    try:
        validate_vuln_type(vuln_data)
    except ValidationError as e:
        logger.exception("Invalid vulnerability type", exc_info=e)
        raise

    try:
        run_date = get_run_date(vuln_data.pop('run_date', None))
    except ValueError as e:
        logger.exception("Could not get run date", exc_info=e)
        raise

    if run_date:
        vuln_data['create_date'] = run_date

    tool = vuln_data.get('tool', '')
    # TODO: Check in professional
    if not tool:
        if command:
            vuln_data['tool'] = command['tool']
        else:
            vuln_data['tool'] = 'Web UI'

    try:
        vuln_data['id'] = db.session.execute("SELECT nextval('vulnerability_id_seq');").scalar()
        logger.debug(f"Vulnerability seq id {vuln_data['id']}")
    except Exception as e:
        logger.error("Could not get vulnerability sequence.", exc_info=e)
        raise

    vuln_data['workspace_id'] = ws.id
    processed_data = set_relationships_data(vuln_data, command)

    if 'host' in vuln_data:
        vuln_data['host_id'] = vuln_data['host'].id
    elif 'service' in vuln_data:
        vuln_data['service_id'] = vuln_data['service'].id
    else:
        logger.error("No service/host object found in vulnerability creation")
        raise ValueError("No service/host object found in vulnerability creation")

    set_cvss_data(vuln_data)

    # TODO: Default 0?
    vuln_data['risk'] = None

    # We need to remove this fields for insert statement. They are not part of sql table.
    vuln_data.pop("host", None)
    vuln_data.pop("service", None)

    # This should not happen but just in case ...
    # Improve this with marshmallow
    # All rows must have the same fields in insert statement
    if 'confirmed' not in vuln_data:
        vuln_data['confirmed'] = False
    if 'status_code' not in vuln_data:
        vuln_data['status_code'] = None
    if 'external_id' not in vuln_data:
        vuln_data['external_id'] = ''
    elif vuln_data['external_id'] is None:
        vuln_data['external_id'] = ''
    if 'impact_integrity' not in vuln_data:
        vuln_data['impact_integrity'] = False
    if 'impact_confidentiality' not in vuln_data:
        vuln_data['impact_confidentiality'] = False

    # TODO: improve
    processed_data[vuln_data['id']]['vuln_data'] = vuln_data

    return processed_data, vuln_data['id']


def set_cvss_data(vuln_data):
    set_cvss3_data(vuln_data)
    set_cvss2(vuln_data)


def set_cvss2(vuln_data):
    init_cvss2_data(vuln_data)
    vs2 = vuln_data.pop('cvss2_vector_string', None)
    if vs2:
        try:
            cvss_instance = cvss.CVSS2(vs2)
            vuln_data['_cvss2_vector_string'] = vs2
            vuln_data['cvss2_base_score'] = get_base_score(cvss_instance)
            vuln_data['cvss2_base_severity'] = get_severity(cvss_instance, 'B')
            vuln_data['cvss2_temporal_score'] = get_temporal_score(cvss_instance)
            vuln_data['cvss2_temporal_severity'] = get_severity(cvss_instance, 'T')
            vuln_data['cvss2_environmental_score'] = get_environmental_score(cvss_instance)
            vuln_data['cvss2_environmental_severity'] = get_severity(cvss_instance, 'E')
            vuln_data['cvss2_access_vector'] = get_propper_value(cvss_instance, 'AV')
            vuln_data['cvss2_access_complexity'] = get_propper_value(cvss_instance, 'AC')
            vuln_data['cvss2_authentication'] = get_propper_value(cvss_instance, 'Au')
            vuln_data['cvss2_confidentiality_impact'] = get_propper_value(cvss_instance, 'C')
            vuln_data['cvss2_integrity_impact'] = get_propper_value(cvss_instance, 'I')
            vuln_data['cvss2_availability_impact'] = get_propper_value(cvss_instance, 'A')
            vuln_data['cvss2_exploitability'] = get_propper_value(cvss_instance, 'E')
            vuln_data['cvss2_remediation_level'] = get_propper_value(cvss_instance, 'RL')
            vuln_data['cvss2_report_confidence'] = get_propper_value(cvss_instance, 'RC')
            vuln_data['cvss2_collateral_damage_potential'] = get_propper_value(cvss_instance, 'CDP')
            vuln_data['cvss2_target_distribution'] = get_propper_value(cvss_instance, 'TD')
            vuln_data['cvss2_confidentiality_requirement'] = get_propper_value(cvss_instance, 'CR')
            vuln_data['cvss2_integrity_requirement'] = get_propper_value(cvss_instance, 'IR')
            vuln_data['cvss2_availability_requirement'] = get_propper_value(cvss_instance, 'AR')
            vuln_data['cvss2_exploitability_score'] = get_exploitability_score(cvss_instance)
            vuln_data['cvss2_impact_score'] = get_impact_score(cvss_instance)
        except Exception as e:
            logger.exception("Could not create cvss2", exc_info=e)


def init_cvss2_data(vuln_data):
    vuln_data['_cvss2_vector_string'] = None
    vuln_data['cvss2_base_score'] = None
    vuln_data['cvss2_base_severity'] = None
    vuln_data['cvss2_temporal_score'] = None
    vuln_data['cvss2_temporal_severity'] = None
    vuln_data['cvss2_environmental_score'] = None
    vuln_data['cvss2_environmental_severity'] = None
    vuln_data['cvss2_access_vector'] = None
    vuln_data['cvss2_access_complexity'] = None
    vuln_data['cvss2_authentication'] = None
    vuln_data['cvss2_confidentiality_impact'] = None
    vuln_data['cvss2_integrity_impact'] = None
    vuln_data['cvss2_availability_impact'] = None
    vuln_data['cvss2_exploitability'] = None
    vuln_data['cvss2_remediation_level'] = None
    vuln_data['cvss2_report_confidence'] = None
    vuln_data['cvss2_collateral_damage_potential'] = None
    vuln_data['cvss2_target_distribution'] = None
    vuln_data['cvss2_confidentiality_requirement'] = None
    vuln_data['cvss2_integrity_requirement'] = None
    vuln_data['cvss2_availability_requirement'] = None
    vuln_data['cvss2_exploitability_score'] = None
    vuln_data['cvss2_impact_score'] = None


def set_cvss3_data(vuln_data):
    init_cvss3_data(vuln_data)
    vs3 = vuln_data.pop('cvss3_vector_string', None)
    if vs3:
        try:
            cvss_instance = cvss.CVSS3(vs3)
            vuln_data['_cvss3_vector_string'] = vs3
            vuln_data['cvss3_base_score'] = get_base_score(cvss_instance)
            vuln_data['cvss3_base_severity'] = get_severity(cvss_instance, 'B')
            vuln_data['cvss3_temporal_score'] = get_temporal_score(cvss_instance)
            vuln_data['cvss3_temporal_severity'] = get_severity(cvss_instance, 'T')
            vuln_data['cvss3_environmental_score'] = get_environmental_score(cvss_instance)
            vuln_data['cvss3_environmental_severity'] = get_severity(cvss_instance, 'E')
            vuln_data['cvss3_attack_vector'] = get_propper_value(cvss_instance, 'AV')
            vuln_data['cvss3_attack_complexity'] = get_propper_value(cvss_instance, 'AC')
            vuln_data['cvss3_privileges_required'] = get_propper_value(cvss_instance, 'PR')
            vuln_data['cvss3_user_interaction'] = get_propper_value(cvss_instance, 'UI')
            vuln_data['cvss3_scope'] = get_propper_value(cvss_instance, 'S')
            vuln_data['cvss3_confidentiality_impact'] = get_propper_value(cvss_instance, 'C')
            vuln_data['cvss3_integrity_impact'] = get_propper_value(cvss_instance, 'I')
            vuln_data['cvss3_availability_impact'] = get_propper_value(cvss_instance, 'A')
            vuln_data['cvss3_exploit_code_maturity'] = get_propper_value(cvss_instance, 'E')
            vuln_data['cvss3_remediation_level'] = get_propper_value(cvss_instance, 'RL')
            vuln_data['cvss3_report_confidence'] = get_propper_value(cvss_instance, 'RC')
            vuln_data['cvss3_confidentiality_requirement'] = get_propper_value(cvss_instance, 'CR')
            vuln_data['cvss3_integrity_requirement'] = get_propper_value(cvss_instance, 'IR')
            vuln_data['cvss3_availability_requirement'] = get_propper_value(cvss_instance, 'AR')
            vuln_data['cvss3_modified_attack_vector'] = get_propper_value(cvss_instance, 'MAV')
            vuln_data['cvss3_modified_attack_complexity'] = get_propper_value(cvss_instance, 'MAC')
            vuln_data['cvss3_modified_privileges_required'] = get_propper_value(cvss_instance, 'MPR')
            vuln_data['cvss3_modified_user_interaction'] = get_propper_value(cvss_instance, 'MUI')
            vuln_data['cvss3_modified_scope'] = get_propper_value(cvss_instance, 'MS')
            vuln_data['cvss3_modified_confidentiality_impact'] = get_propper_value(cvss_instance, 'MC')
            vuln_data['cvss3_modified_integrity_impact'] = get_propper_value(cvss_instance, 'MI')
            vuln_data['cvss3_modified_availability_impact'] = get_propper_value(cvss_instance, 'MA')
            vuln_data['cvss3_exploitability_score'] = get_exploitability_score(cvss_instance)
            vuln_data['cvss3_impact_score'] = get_impact_score(cvss_instance)
        except Exception as e:
            logger.exception("Could not create cvss3", exc_info=e)


def init_cvss3_data(vuln_data):
    vuln_data['_cvss3_vector_string'] = None
    vuln_data['cvss3_base_score'] = None
    vuln_data['cvss3_base_severity'] = None
    vuln_data['cvss3_temporal_score'] = None
    vuln_data['cvss3_temporal_severity'] = None
    vuln_data['cvss3_environmental_score'] = None
    vuln_data['cvss3_environmental_severity'] = None
    vuln_data['cvss3_attack_vector'] = None
    vuln_data['cvss3_attack_complexity'] = None
    vuln_data['cvss3_privileges_required'] = None
    vuln_data['cvss3_user_interaction'] = None
    vuln_data['cvss3_scope'] = None
    vuln_data['cvss3_confidentiality_impact'] = None
    vuln_data['cvss3_integrity_impact'] = None
    vuln_data['cvss3_availability_impact'] = None
    vuln_data['cvss3_exploit_code_maturity'] = None
    vuln_data['cvss3_remediation_level'] = None
    vuln_data['cvss3_report_confidence'] = None
    vuln_data['cvss3_confidentiality_requirement'] = None
    vuln_data['cvss3_integrity_requirement'] = None
    vuln_data['cvss3_availability_requirement'] = None
    vuln_data['cvss3_modified_attack_vector'] = None
    vuln_data['cvss3_modified_attack_complexity'] = None
    vuln_data['cvss3_modified_privileges_required'] = None
    vuln_data['cvss3_modified_user_interaction'] = None
    vuln_data['cvss3_modified_scope'] = None
    vuln_data['cvss3_modified_confidentiality_impact'] = None
    vuln_data['cvss3_modified_integrity_impact'] = None
    vuln_data['cvss3_modified_availability_impact'] = None
    vuln_data['cvss3_exploitability_score'] = None
    vuln_data['cvss3_impact_score'] = None


def set_relationships_data(vulnerability, command):

    vulnerability.pop('_attachments', {})
    references = vulnerability.pop('refs', [])
    cve_list = vulnerability.pop('cve', [])
    cwe_list = vulnerability.pop('cwe', [])
    policyviolations = vulnerability.pop('policy_violations', [])
    owasp_list = vulnerability.pop('owasp', [])

    vuln_sequence_id = vulnerability['id']

    processed_data = {
        vuln_sequence_id: {
            'references': [],
            'command': None,
            'cve_associations': [],
            'owasp_objects': [],
            'cwe_associations': [],
            'policy_violations_associations': [],
            'vuln_data': None
        }
    }

    parsed_cve_list = []
    for cve in cve_list:
        parsed_cve_list += re.findall(CVE.CVE_PATTERN, cve.upper())
    for parsed_cve in parsed_cve_list:
        cve = create_cve_obj(parsed_cve)
        if cve:
            logger.debug(f"Associating vuln {vuln_sequence_id} with cve {cve.id} ({cve.name})")
            processed_data[vuln_sequence_id]['cve_associations'].append(
                {
                    'vulnerability_id': vuln_sequence_id,
                    'cve_id': cve.id
                }
            )
        else:
            logger.error(f"Could not create CVE {parsed_cve}")

    cmd = _create_command_json(vulnerability['workspace_id'], vuln_sequence_id, command)
    if cmd:
        processed_data[vuln_sequence_id]['command'] = cmd

    for owasp in owasp_list:
        owasp_obj = get_or_create_owasp(owasp)
        if owasp_obj:
            logger.debug(f"Associating vuln {vuln_sequence_id} with owasp {owasp_obj.id} ({owasp_obj.name})")
            processed_data[vuln_sequence_id]['owasp_objects'].append(
                {
                    'vulnerability_id': vuln_sequence_id,
                    'owasp_id': owasp_obj.id
                }
            )

    for reference in references:
        reference['vulnerability_id'] = vuln_sequence_id
        logger.debug(f"Associating vuln {vuln_sequence_id} with reference {reference['name']}")
        processed_data[vuln_sequence_id]['references'].append(reference)

    for cwe in cwe_list:
        cwe_obj = get_or_create_cwe(cwe['name'])
        if cwe_obj:
            processed_data[vuln_sequence_id]['cwe_associations'].append(
                {'vulnerability_id': vuln_sequence_id,
                 'cwe_id': cwe_obj.id
                 }
            )

    for policy in policyviolations:
        policy_obj = create_policy_violation_obj(policy, vulnerability['workspace_id'])
        if policy_obj:
            processed_data[vuln_sequence_id]['policy_violations_associations'].append(
                {
                    'vulnerability_id': vuln_sequence_id,
                    'policy_violation_id': policy_obj.id
                }
            )

    return processed_data


def _create_hostvuln(ws, host, vuln_data, command: dict):
    return _create_vuln(ws, vuln_data, command, host=host)


def _create_servicevuln(ws, service, vuln_data, command: dict):
    return _create_vuln(ws, vuln_data, command, service=service)


def _create_credential(ws, cred_data, command: dict, **kwargs):
    cred_data = cred_data.copy()
    cred_data.update(kwargs)
    created, cred = get_or_create(ws, Credential, cred_data)
    db.session.commit()

    if command is not None:
        _create_command_object_for(ws, created, cred, command)


class BulkCreateView(GenericWorkspacedView):
    route_base = 'bulk_create'
    schema_class = BulkCreateSchema

    def post(self, workspace_name):
        """
        ---
          tags: ["Bulk"]
          description: Creates all faraday objects in bulk for a workspace
          requestBody:
            required: true
            content:
                application/json:
                    schema: BulkCreateSchema
          responses:
            201:tags:
              description: Created
              content:
                application/json:
                  schema: BulkCreateSchema
            401:
               $ref: "#/components/responses/UnauthorizedError"
            403:
               description: Disabled workspace
            404:
               description: Workspace not found
        """
        agent = None

        if flask_login.current_user.is_anonymous:
            agent = require_agent_token()
        data = self._parse_data(self._get_schema_instance({}), flask.request)
        json_data = flask.request.json
        workspace = get_workspace(workspace_name)

        if 'execution_id' in data:
            if not workspace:
                abort(404, f"No such workspace: {workspace_name}")

            execution_id = data["execution_id"]

            agent_execution: AgentExecution = AgentExecution.query.filter(
                AgentExecution.id == execution_id
            ).one_or_none()

            if agent_execution is None:
                logger.exception(
                    NoResultFound(
                        f"No row was found for agent executor id {execution_id}")
                )
                abort(400, "Can not find an agent execution with that id")

            if workspace_name != agent_execution.workspace.name:
                logger.exception(
                    ValueError(f"The {agent.name} agent has permission to workspace {workspace_name} and ask to write "
                               f"to workspace {agent_execution.workspace.name}")
                )
                abort(400, "Trying to write to the incorrect workspace")
            command = Command.query.filter(Command.id == agent_execution.command.id).one_or_none()
            if command is None:
                logger.exception(
                    ValueError(f"There is no command with {agent_execution.command.id}")
                )
                abort(400, "Trying to update a not existent command")
            db.session.flush()
        else:
            if flask_login.current_user.is_anonymous:
                flask.abort(400, "argument expected: execution_id")

            command = Command(**(data['command']))
            command.workspace = workspace
            db.session.add(command)
            db.session.commit()

        if data['hosts']:
            # Create random file
            chars = string.ascii_uppercase + string.digits
            random_prefix = ''.join(random.choice(chars) for _ in range(30))  # nosec
            json_file = f"{random_prefix}.json"
            file_path = CONST_FARADAY_HOME_PATH / 'uploaded_reports' / json_file
            with file_path.open('w') as output:
                json.dump(json_data, output)
            logger.info("Create tmp json file for bulk_create: %s", file_path)
            user_id = flask_login.current_user.id if not flask_login.current_user.is_anonymous else None
            if faraday_server.celery_enabled:
                from faraday.server.utils.reports_processor import process_report  # pylint: disable=import-outside-toplevel
                process_report(workspace.name,
                               command.id,
                               file_path,
                               None,
                               user_id,
                               False,
                               False,
                               None,
                               None,
                               None)
                logger.info(f"Faraday objects sent to celery in bulk for workspace {workspace}")
            else:
                from faraday.server.utils.reports_processor import REPORTS_QUEUE  # pylint: disable=import-outside-toplevel
                REPORTS_QUEUE.put(
                    (
                        workspace.name,
                        command.id,
                        file_path,
                        None,
                        user_id,
                        False,
                        False,
                        None,
                        None,
                        None
                    )
                )
                logger.info(f"Faraday objects enqueued in bulk for workspace {workspace}")
        else:
            logger.warning("No hosts parsed in data...")
            logger.warning(data)
            logger.warning(json_data)
            _update_command(command.id, data['command'])
        return flask.jsonify(
            {
                "message": "Created",
                "command_id": command.id
            }
        ), 201

    post.is_public = True


BulkCreateView.register(bulk_create_api)
