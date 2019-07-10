import flask
import sqlalchemy
from marshmallow import (
    fields,
    post_load,
    Schema,
    utils,
    ValidationError,
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
)
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation
    )
from faraday.server.api.modules import (
    hosts,
    services,
    vulns,
)
from faraday.server.api.base import AutoSchema, GenericWorkspacedView

bulk_create_api = flask.Blueprint('bulk_create_api', __name__)

class VulnerabilitySchema(vulns.VulnerabilitySchema):
    class Meta(vulns.VulnerabilitySchema.Meta):
        fields = tuple(
            field_name for field_name in vulns.VulnerabilitySchema.Meta.fields
            if field_name not in ('parent', 'parent_type')
        )


class VulnerabilityWebSchema(vulns.VulnerabilityWebSchema):
    class Meta(vulns.VulnerabilityWebSchema.Meta):
        fields = tuple(
            field_name for field_name in vulns.VulnerabilityWebSchema.Meta.fields
            if field_name not in ('parent', 'parent_type')
        )


class PolymorphicVulnerabilityField(fields.Field):
    """Used like a nested field with many objects, but it decides which
    schema to use based on the type of each vuln"""
    def __init__(self, *args, **kwargs):
        super(PolymorphicVulnerabilityField, self).__init__(*args, **kwargs)
        self.many = kwargs.get('many', False)
        self.vuln_schema = VulnerabilitySchema(strict=True)
        self.vulnweb_schema = VulnerabilityWebSchema(strict=True)

    def _deserialize(self, value, attr, data):
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
        return schema.load(value).data


class CredentialSchema(AutoSchema):
    class Meta:
        model = Credential
        fields = ('username', 'password', 'description', 'name')


class ServiceSchema(services.ServiceSchema):
    """It's like the original service schema, but now it only uses port
    instead of ports (a single integer array). That field was only used
    to keep backwards compatibility with the Web UI"""
    port = fields.Integer(strict=True, required=True,
                          validate=[Range(min=0, error="The value must be greater than or equal to 0")])
    vulnerabilities = PolymorphicVulnerabilityField(
        VulnerabilitySchema(many=True),
        many=True,
        missing=[],
    )
    credentials = fields.Nested(
        CredentialSchema(many=True),
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


class HostSchema(hosts.HostSchema):
    services = fields.Nested(
        ServiceSchema(many=True, context={'updating': False}),
        many=True,
        missing=[],
    )
    vulnerabilities = fields.Nested(
        VulnerabilitySchema(many=True),
        many=True,
        missing=[],
    )
    credentials = fields.Nested(
        CredentialSchema(many=True),
        many=True,
        missing=[],
    )

    class Meta(hosts.HostSchema.Meta):
        fields = hosts.HostSchema.Meta.fields + ('services', 'vulnerabilities')


class CommandSchema(AutoSchema):
    """The schema of faraday/server/api/modules/commandsrun.py has a lot
    of ugly things because of the Web UI backwards compatibility.

    I don't need that here, so I'll write a schema from scratch."""

    duration = fields.TimeDelta('seconds', required=True)

    class Meta:
        model = Command
        fields = (
            'command', 'duration', 'start_date', 'ip', 'hostname', 'params',
            'user', 'creator', 'tool', 'import_source',
        )

    @post_load
    def load_end_date(self, data):
        duration = data.pop('duration')
        data['end_date'] = data['start_date'] + duration


class BulkCreateSchema(Schema):
    hosts = fields.Nested(
        HostSchema(many=True),
        many=True,
        missing=[],
    )
    command = fields.Nested(
        CommandSchema(),
        required=False,
    )


def get_or_create(ws, model_class, data):
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


def bulk_create(ws, data, reload_data=True):
    if reload_data:
        schema = BulkCreateSchema(strict=True)
        data = schema.load(data).data
    if 'command' in data:
        command = create_command(ws, data['command'], False)
    else:
        command = None
    for host in data['hosts']:
        create_host(ws, host, command, False)


def create_command(ws, command_data, reload_data=True):
    if reload_data:
        schema = CommandSchema(strict=True)
        command_data = schema.load(command_data).data
    (created, command) = get_or_create(ws, Command, command_data)
    assert created  # There isn't an unique constraint in command
    return command


def create_host(ws, host_data, command=None, reload_data=True):
    if reload_data:
        schema = HostSchema(strict=True)
        host_data = schema.load(host_data).data
    hostnames = host_data.pop('hostnames', [])
    services = host_data.pop('services')
    credentials = host_data.pop('credentials')
    vulns = host_data.pop('vulnerabilities')
    (created, host) = get_or_create(ws, Host, host_data)
    if created:
        for name in hostnames:
            db.session.add(Hostname(name=name, host=host, workspace=ws))
    db.session.commit()

    if command is not None:
        create_command_object_for(ws, created, host, command)

    for service_data in services:
        create_service(ws, host, service_data, command, False)

    for vuln_data in vulns:
        create_hostvuln(ws, host, vuln_data, command, False)

    for cred_data in credentials:
        create_credential(ws, cred_data, command, False, host=host)


def create_command_object_for(ws, created, obj, command):
    assert command is not None
    db.session.add(CommandObject(
        obj,
        command=command,
        created_persistent=created,
        workspace=ws))
    db.session.commit()


def create_service(ws, host, service_data, command=None, reload_data=True):
    if reload_data:
        schema = ServiceSchema(strict=True, context={'updating': False})
        service_data = schema.load(service_data).data
    vulns = service_data.pop('vulnerabilities')
    creds = service_data.pop('credentials')
    service_data['host'] = host
    (created, service) = get_or_create(ws, Service, service_data)
    db.session.commit()

    if command is not None:
        create_command_object_for(ws, created, service, command)

    for vuln_data in vulns:
        create_servicevuln(ws, service, vuln_data, command, False)

    for cred_data in creds:
        create_credential(ws, cred_data, command, False, service=service)


def create_vuln(ws, vuln_data, command=None, reload_data=True, **kwargs):
    """Create standard or web vulnerabilites"""
    assert 'host' in kwargs or 'service' in kwargs
    assert not ('host' in kwargs and 'service' in kwargs)

    if reload_data:
        if 'host' in kwargs:
            # Only allow standard vulns
            schema = VulnerabilitySchema(strict=True)
            vuln_data = schema.load(vuln_data).data
        else:
            vuln_data = PolymorphicVulnerabilityField()._deserialize_item(vuln_data)

    attachments = vuln_data.pop('_attachments', {})
    references = vuln_data.pop('references', [])
    policyviolations = vuln_data.pop('policy_violations', [])

    vuln_data.update(kwargs)
    if 'host' in kwargs and vuln_data['type'] != 'vulnerability':
        raise ValidationError('Type must be "Vulnerability"')
    if vuln_data['type'] == 'vulnerability':
        model_class = Vulnerability
    elif vuln_data['type'] == 'vulnerability_web':
        model_class = VulnerabilityWeb
    else:
        raise ValidationError("unknown type")

    (created, vuln) = get_or_create(ws, model_class, vuln_data)
    db.session.commit()

    if command is not None:
        create_command_object_for(ws, created, vuln, command)

    if created:
        vuln.references = references
        vuln.policyviolations = policyviolations
        # TODO attachments
        db.session.add(vuln)
        db.session.commit()


def create_hostvuln(ws, host, vuln_data, command=None, reload_data=True):
    create_vuln(ws, vuln_data, command, reload_data, host=host)


def create_servicevuln(ws, service, vuln_data, command=None, reload_data=True):
    create_vuln(ws, vuln_data, command, reload_data, service=service)


def create_credential(ws, cred_data, command=None, reload_data=True, **kwargs):
    if reload_data:
        schema = CredentialSchema(strict=True)
        cred_data = schema.load(cred_data).data
    cred_data.update(kwargs)
    (created, cred) = get_or_create(ws, Credential, cred_data)
    db.session.commit()

    if command is not None:
        create_command_object_for(ws, created, cred, command)


class BulkCreateView(GenericWorkspacedView):
    route_base = 'bulk_create'
    schema_class = BulkCreateSchema

    def post(self, workspace_name):
        data = self._parse_data(self._get_schema_instance({}), flask.request)
        bulk_create(self._get_workspace(workspace_name), data, False)
        return "Created", 201

BulkCreateView.register(bulk_create_api)
