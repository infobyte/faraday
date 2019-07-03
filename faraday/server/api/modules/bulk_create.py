import sqlalchemy
from marshmallow import fields, ValidationError
from marshmallow.validate import Range
from faraday.server.models import (
    db,
    Host,
    Hostname,
    Service,
    Vulnerability,
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


class VulnerabilitySchema(vulns.VulnerabilitySchema):
    class Meta(vulns.VulnerabilitySchema.Meta):
        fields = tuple(
            field_name for field_name in vulns.VulnerabilitySchema.Meta.fields
            if field_name not in ('parent', 'parent_type')
        )


class ServiceSchema(services.ServiceSchema):
    """It's like the original service schema, but now it only uses port
    instead of ports (a single integer array). That field was only used
    to keep backwards compatibility with the Web UI"""
    port = fields.Integer(strict=True, required=True,
                          validate=[Range(min=0, error="The value must be greater than or equal to 0")])
    vulnerabilities = fields.Nested(
        VulnerabilitySchema(many=True),
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

    class Meta(hosts.HostSchema.Meta):
        fields = hosts.HostSchema.Meta.fields + ('services', 'vulnerabilities')


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
            return (False, obj)
        else:
            raise
    # self._set_command_id(obj, True)  # TODO check this
    return (True, obj)


def bulk_create(ws, data):
    for host in data['hosts']:
        create_host(ws, host)


def create_host(ws, raw_data):
    schema = HostSchema(strict=True)
    host_data = schema.load(raw_data).data
    hostnames = host_data.pop('hostnames', [])
    services = host_data.pop('services')
    vulns = host_data.pop('vulnerabilities')
    (created, host) = get_or_create(ws, Host, host_data)
    if created:
        for name in hostnames:
            db.session.add(Hostname(name=name, host=host, workspace=ws))
    db.session.commit()

    for service_data in services:
        create_service(ws, host, service_data)

    for vuln_data in vulns:
        create_hostvuln(ws, host, vuln_data, False)


def create_service(ws, host, raw_data):
    schema = ServiceSchema(strict=True, context={'updating': False})
    service_data = schema.load(raw_data).data
    vulns = service_data.pop('vulnerabilities')
    service_data['host'] = host
    (_, service) = get_or_create(ws, Service, service_data)
    db.session.commit()

    for vuln_data in vulns:
        create_servicevuln(ws, service, vuln_data, False)


def create_vuln(ws, vuln_data, reload_data=True, **kwargs):
    if reload_data:
        schema = VulnerabilitySchema(strict=True)
        vuln_data = schema.load(vuln_data).data

    attachments = vuln_data.pop('_attachments', {})
    references = vuln_data.pop('references', [])
    policyviolations = vuln_data.pop('policy_violations', [])

    vuln_data.update(kwargs)
    if vuln_data['type'] != 'vulnerability':
        raise ValidationError('Type must be "Vulnerability"')
    (created, vuln) = get_or_create(ws, Vulnerability, vuln_data)
    db.session.commit()

    if created:
        vuln.references = references
        vuln.policyviolations = policyviolations
        # TODO attachments
        db.session.add(vuln)
        db.session.commit()


def create_hostvuln(ws, host, vuln_data, reload_data=True):
    create_vuln(ws, vuln_data, reload_data, host=host)


def create_servicevuln(ws, service, vuln_data, reload_data=True):
    create_vuln(ws, vuln_data, reload_data, service=service)
