import logging
from datetime import datetime, timedelta
from typing import Type, Optional
import string
import random
import json

import time
import flask_login
import flask
import sqlalchemy
from sqlalchemy.orm.exc import NoResultFound
from marshmallow import (
    fields,
    post_load,
    Schema,
    utils,
    ValidationError,
    validates_schema,
)
from marshmallow.validate import Range
from faraday.server.models import (
    Command,
    CommandObject,
    Credential,
    db,
    Host,
    Hostname,
    Service,
    Vulnerability,
    VulnerabilityWeb,
    AgentExecution,
    Workspace,
    Metadata
)
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation,
    get_object_type_for)
from faraday.server.api.modules import (
    hosts,
    services,
    vulns,
)
from faraday.server.api.base import AutoSchema, GenericWorkspacedView
from faraday.server.api.modules.websocket_auth import require_agent_token
from faraday.server.config import CONST_FARADAY_HOME_PATH

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
        except AttributeError:
            raise ValidationError("Value is expected to be an object")
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
        # VulnerabilitySchema(many=True),  # I have no idea what this line does, but breaks with marshmallow 3
        many=True,
        missing=[],
    )
    credentials = fields.Nested(
        BulkCredentialSchema(many=True),
        many=True,
        missing=[],
    )

    def post_load_parent(self, data):
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
    obj = model_class(**data)
    obj.workspace = ws
    # assert not db.session.new
    try:
        db.session.add(obj)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError as ex:
        if not is_unique_constraint_violation(ex):
            raise
        db.session.rollback()
        conflict_obj = get_conflict_object(db.session, obj, data, ws)
        if conflict_obj:
            return (False, conflict_obj)
        else:
            raise
    # self._set_command_id(obj, True)  # TODO check this
    return (True, obj)


def bulk_create(ws: Workspace,
                command: Optional[Command],
                data: dict,
                data_already_deserialized: bool = False,
                set_end_date: bool = True):

    logger.info("Init bulk create process")
    start_time = time.time()

    if not data_already_deserialized:
        schema = BulkCreateSchema()
        data = schema.load(data)

    if 'command' in data:
        command = _update_command(command, data['command'])

    total_hosts = len(data['hosts'])
    if total_hosts > 0:
        logger.debug(f"Needs to create {total_hosts} hosts...")
        for host in data['hosts']:
            _create_host(ws, host, command)

    if 'command' in data and set_end_date:
        command.end_date = datetime.utcnow() if command.end_date is None else \
            command.end_date
        db.session.commit()

    total_secs = time.time() - start_time
    logger.info(f"Finish bulk create process. Total time: {total_secs:.2f} secs")


def _update_command(command: Command, command_data: dict):
    db.session.query(Command).filter(Command.id == command.id).update(command_data)
    db.session.commit()
    return command


def _create_host(ws, host_data, command=None):
    hostnames = host_data.pop('hostnames', [])
    services = host_data.pop('services')
    credentials = host_data.pop('credentials')
    vulns = host_data.pop('vulnerabilities')
    (created, host) = get_or_create(ws, Host, host_data)
    for name in set(hostnames).difference(set(map(lambda x: x.name, host.hostnames))):
        db.session.add(Hostname(name=name, host=host, workspace=ws))
    db.session.commit()

    if command is not None:
        _create_command_object_for(ws, created, host, command)

    total_services = len(services)
    if total_services > 0:
        logger.debug(f"Needs to create {total_services} services...")
        for service_data in services:
            _create_service(ws, host, service_data, command)

    total_vulns = len(vulns)
    if total_vulns > 0:
        logger.debug(f"Needs to create {total_vulns} vulns...")
        for vuln_data in vulns:
            _create_hostvuln(ws, host, vuln_data, command)

    total_credentials = len(credentials)
    if total_credentials > 0:
        logger.debug(f"Needs to create {total_credentials} credentials...")
        for cred_data in credentials:
            _create_credential(ws, cred_data, command, host=host)


def _create_command_object_for(ws, created, obj, command):
    assert command is not None
    data = {
        'object_id': obj.id,
        'object_type': get_object_type_for(obj),
        'command': command,
        'created_persistent': created,
        'workspace': ws,
    }
    get_or_create(ws, CommandObject, data)
    db.session.commit()


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


def _create_service(ws, host, service_data, command=None):
    service_data = service_data.copy()
    vulns = service_data.pop('vulnerabilities')
    creds = service_data.pop('credentials')
    service_data['host'] = host
    (created, service) = get_or_create(ws, Service, service_data)

    if not created:
        service = _update_service(service, service_data)
    db.session.commit()

    if command is not None:
        _create_command_object_for(ws, created, service, command)

    total_service_vulns = len(vulns)
    if total_service_vulns > 0:
        logger.debug(f"Needs to create {total_service_vulns} service vulns...")
        for vuln_data in vulns:
            _create_servicevuln(ws, service, vuln_data, command)

    total_service_creds = len(creds)
    if total_service_creds > 0:
        logger.debug(f"Needs to create {total_service_creds} service credentials...")
        for cred_data in creds:
            _create_credential(ws, cred_data, command, service=service)


def _create_vuln(ws, vuln_data, command=None, **kwargs):
    """Create standard or web vulnerabilites"""
    assert 'host' in kwargs or 'service' in kwargs
    assert not ('host' in kwargs and 'service' in kwargs)

    vuln_data.pop('_attachments', {})
    references = vuln_data.pop('references', [])
    policyviolations = vuln_data.pop('policy_violations', [])

    vuln_data = vuln_data.copy()
    vuln_data.update(kwargs)
    if 'host' in kwargs and vuln_data['type'] != 'vulnerability':
        raise ValidationError('Type must be "Vulnerability"')
    if vuln_data['type'] == 'vulnerability':
        model_class = Vulnerability
    elif vuln_data['type'] == 'vulnerability_web':
        model_class = VulnerabilityWeb
    else:
        raise ValidationError("unknown type")
    tool = vuln_data.get('tool', '')
    if not tool:
        if command:
            vuln_data['tool'] = command.tool
        else:
            vuln_data['tool'] = 'Web UI'

    run_date_string = vuln_data.pop('run_date', None)
    if run_date_string:
        try:
            run_timestamp = float(run_date_string)
            run_date = datetime.utcfromtimestamp(run_timestamp)
            if run_date < datetime.utcnow() + timedelta(hours=24):
                logger.debug("Valid run date")
            else:
                run_date = None
                logger.debug("Run date (%s) is greater than allowed", run_date)
        except ValueError:
            logger.error("Error converting [%s] to a valid date", run_date_string)
    else:
        run_date = None
    (created, vuln) = get_or_create(ws, model_class, vuln_data)
    if created and run_date:
        logger.debug("Apply run date to vuln")
        vuln.create_date = run_date
        db.session.commit()
    elif not created and ("custom_fields" in vuln_data and any(vuln_data["custom_fields"])):
        # Updates Custom Fields
        vuln.custom_fields = vuln_data.pop('custom_fields', {})
        db.session.commit()

    if command is not None:
        _create_command_object_for(ws, created, vuln, command)

    def update_vuln(policyviolations, references, vuln):
        vuln.references = references
        vuln.policy_violations = policyviolations
        # TODO attachments
        db.session.add(vuln)
        db.session.commit()

    if created:
        update_vuln(policyviolations, references, vuln)
    elif vuln.status == "closed":  # Implicit not created
        vuln.status = "re-opened"
        update_vuln(policyviolations, references, vuln)


def _create_hostvuln(ws, host, vuln_data, command=None):
    _create_vuln(ws, vuln_data, command, host=host)


def _create_servicevuln(ws, service, vuln_data, command=None):
    _create_vuln(ws, vuln_data, command, service=service)


def _create_credential(ws, cred_data, command=None, **kwargs):
    cred_data = cred_data.copy()
    cred_data.update(kwargs)
    (created, cred) = get_or_create(ws, Credential, cred_data)
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
        from faraday.server.threads.reports_processor import REPORTS_QUEUE  # pylint: disable=import-outside-toplevel

        if flask_login.current_user.is_anonymous:
            agent = require_agent_token()
        data = self._parse_data(self._get_schema_instance({}), flask.request)
        json_data = flask.request.json
        if flask_login.current_user.is_anonymous:
            workspace = self._get_workspace(workspace_name)

            if not workspace or workspace not in agent.workspaces:
                flask.abort(404, f"No such workspace: {workspace_name}")

            if "execution_id" not in data:
                flask.abort(400, "argument expected: execution_id")

            execution_id = data["execution_id"]

            agent_execution: AgentExecution = AgentExecution.query.filter(
                AgentExecution.id == execution_id
            ).one_or_none()

            if agent_execution is None:
                logger.exception(
                    NoResultFound(
                        f"No row was found for agent executor id {execution_id}")
                )
                flask.abort(400, "Can not find an agent execution with that id")

            if workspace_name != agent_execution.workspace.name:
                logger.exception(
                    ValueError(f"The {agent.name} agent has permission to workspace {workspace_name} and ask to write "
                               f"to workspace {agent_execution.workspace.name}")
                )
                flask.abort(400, "Trying to write to the incorrect workspace")

            params_data = agent_execution.parameters_data
            params = ', '.join([f'{key}={value}' for (key, value) in params_data.items()])

            start_date = (data["command"].get("start_date") or agent_execution.command.start_date) \
                if "command" in data else agent_execution.command.start_date

            end_date = data["command"].get("end_date", None) if "command" in data else None

            data["command"] = {
                'id': agent_execution.command.id,
                'tool': agent.name,  # Agent name
                'command': agent_execution.executor.name,
                'user': '',
                'hostname': '',
                'params': params,
                'import_source': 'agent',
                'start_date': start_date
            }

            if end_date is not None:
                data["command"]["end_date"] = end_date

            command = Command.query.filter(Command.id == agent_execution.command.id).one_or_none()
            if command is None:
                logger.exception(
                    ValueError(f"There is no command with {agent_execution.command.id}")
                )
                flask.abort(400, "Trying to update a not existent command")

            _update_command(command, data['command'])
            db.session.flush()
            if data['hosts']:
                json_data['command'] = data["command"]
                json_data['command']["start_date"] = data["command"]["start_date"].isoformat()
                if 'end_date' in data["command"]:
                    json_data['command']["end_date"] = data["command"]["end_date"].isoformat()

        else:
            workspace = self._get_workspace(workspace_name)
            command = Command(**(data['command']))
            command.workspace = workspace
            db.session.add(command)
            db.session.commit()
        if data['hosts']:
            # Create random file
            chars = string.ascii_uppercase + string.digits
            random_prefix = ''.join(random.choice(chars) for x in range(30))  # nosec
            json_file = f"{random_prefix}.json"
            file_path = CONST_FARADAY_HOME_PATH / 'uploaded_reports' \
                        / json_file
            with file_path.open('w') as output:
                json.dump(json_data, output)
            logger.info("Create tmp json file for bulk_create: %s", file_path)
            user_id = flask_login.current_user.id if not flask_login.current_user.is_anonymous else None
            REPORTS_QUEUE.put(
                (
                    workspace.name,
                    command.id,
                    file_path,
                    None,
                    user_id
                )
            )
        return flask.jsonify(
            {
                "message": "Created",
                "command_id": None if command is None else command.id
            }
        ), 201

    post.is_public = True


BulkCreateView.register(bulk_create_api)
