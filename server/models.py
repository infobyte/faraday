# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declared_attr
from flask_sqlalchemy import SQLAlchemy
from flask_security import (
    RoleMixin,
    UserMixin,
)

import server.config

db = SQLAlchemy()

SCHEMA_VERSION = 'W.3.0.0'


class DatabaseMetadata(db.Model):
    __tablename__ = 'db_metadata'
    id = Column(Integer, primary_key=True)
    option = Column(String(250), nullable=False)
    value = Column(String(250), nullable=False)


class EntityMetadata(db.Model):
    __tablename__ = 'metadata'
    __table_args__ = (
        UniqueConstraint('couchdb_id'),
    )

    id = Column(Integer, primary_key=True)
    update_time = Column(Float, nullable=True)
    update_user = Column(String(250), nullable=True)
    update_action = Column(Integer, nullable=True)
    create_time = Column(Float, nullable=True)
    update_controller_action = Column(String(250), nullable=True)
    creator = Column(String(250), nullable=True)
    owner = Column(String(250), nullable=True)
    command_id = Column(String(250), nullable=True)

    couchdb_id = Column(String(250))
    revision = Column(String(250))
    document_type = Column(String(250))


class SourceCode(db.Model):
    __tablename__ = 'source_code'
    id = Column(Integer, primary_key=True)
    filename = Column(Text, nullable=False)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', backref='source_codes')

    __table_args__ = (
        UniqueConstraint(filename, workspace_id, name='uix_source_code_filename_workspace'),
    )


class Host(db.Model):
    __tablename__ = 'host'
    id = Column(Integer, primary_key=True)
    ip = Column(Text, nullable=False)  # IP v4 or v6
    description = Column(Text, nullable=True)
    os = Column(Text, nullable=True)

    owned = Column(Boolean, nullable=False, default=False)

    default_gateway_ip = Column(Text, nullable=True)
    default_gateway_mac = Column(Text, nullable=True)

    mac = Column(Text, nullable=True)
    net_segment = Column(Text, nullable=True)

    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)
    entity_metadata = relationship(
                                EntityMetadata,
                                uselist=False,
                                cascade="all, delete-orphan",
                                single_parent=True,
                                foreign_keys=[entity_metadata_id]
                                )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
                            'Workspace',
                            backref='hosts',
                            foreign_keys=[workspace_id]
                            )
    __table_args__ = (
        UniqueConstraint(ip, workspace_id, name='uix_host_ip_workspace'),
    )


class Hostname(db.Model):
    __tablename__ = 'hostname'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    host_id = Column(Integer, ForeignKey('host.id'), index=True, nullable=False)
    host = relationship('Host', backref='hostnames')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref='hosts',
        foreign_keys=[workspace_id]
    )
    __table_args__ = (
        UniqueConstraint(name, host_id, workspace_id, name='uix_hostname_host_workspace'),
    )


class Service(db.Model):
    STATUSES = [
        'open',
        'closed',
        'filtered'
    ]
    __tablename__ = 'service'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    port = Column(Integer, nullable=False)
    owned = Column(Boolean, nullable=False, default=False)

    protocol = Column(Text, nullable=False)
    status = Column(Enum(*STATUSES, name='service_statuses'), nullable=True)
    version = Column(Text, nullable=True)

    banner = Column(Text, nullable=True)

    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)
    entity_metadata = relationship(
                                EntityMetadata,
                                uselist=False,
                                cascade="all, delete-orphan",
                                single_parent=True,
                                foreign_keys=[entity_metadata_id]
                                )

    host_id = Column(Integer, ForeignKey('host.id'), index=True, nullable=False)
    host = relationship('Host', backref='services', foreign_keys=[host_id])

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
                            'Workspace',
                            backref='services',
                            foreign_keys=[workspace_id]
                            )
    __table_args__ = (
        UniqueConstraint(port, protocol, host_id, workspace_id, name='uix_service_port_protocol_host_workspace'),
    )


class VulnerabilityABC(db.Model):
    # revisar plugin nexpose, netspark para terminar de definir uniques. asegurar que se carguen bien
    EASE_OF_RESOLUTIONS = [
        'trivial',
        'simple',
        'moderate',
        'difficult',
        'infeasible'
    ]
    SEVERITIES = [
        'critical',
        'high',
        'medium',
        'low',
        'informational',
        'unclassified',
    ]

    __abstract__ = True
    id = Column(Integer, primary_key=True)

    data = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    ease_of_resolution = Column(Enum(*EASE_OF_RESOLUTIONS, name='vulnerability_ease_of_resolution'), nullable=True)
    name = Column(Text, nullable=False)
    resolution = Column(Text, nullable=True)
    severity = Column(Enum(*SEVERITIES, name='vulnerability_severity'), nullable=False)
    # TODO add evidence

    impact_accountability = Column(Boolean, default=False)
    impact_availability = Column(Boolean, default=False)
    impact_confidentiality = Column(Boolean, default=False)
    impact_integrity = Column(Boolean, default=False)


class VulnerabilityTemplate(VulnerabilityABC):
    __tablename__ = 'vulnerability_template'

    __table_args__ = (
        UniqueConstraint('name', name='uix_vulnerability_template_name'),
    )


class VulnerabilityGeneric(VulnerabilityABC):
    STATUSES = [
        'open',
        'closed',
        're-opened',
        'risk-accepted'
    ]
    VULN_TYPES = [
        'vulnerability',
        'vulnerability_web',
        'vulnerability_code'
    ]

    __tablename__ = 'vulnerability'
    confirmed = Column(Boolean, nullable=False, default=False)
    status = Column(Enum(*STATUSES, name='vulnerability_statuses'), nullable=False, default="open")
    type = Column(Enum(*VULN_TYPES, name='vulnerability_types'), nullable=False)

    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True,
                        nullable=False,
                        )
    workspace = relationship('Workspace', backref='vulnerabilities')

    __mapper_args__ = {
        'polymorphic_on': type
    }


class Vulnerability(VulnerabilityGeneric):
    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship(
                    'Host',
                    backref='vulnerabilities',
                    foreign_keys=[host_id],
                    )

    service_id = Column(Integer, ForeignKey(Service.id))
    service = relationship(
                    'Service',
                    backref='vulnerabilities',
                    )

    __table_args__ = {
        'extend_existing': True
    }

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[0]
    }


class VulnerabilityWeb(VulnerabilityGeneric):
    method = Column(String(50), nullable=True)
    parameters = Column(String(500), nullable=True)
    parameter_name = Column(String(250), nullable=True)
    path = Column(String(500), nullable=True)
    query = Column(Text(), nullable=True)
    request = Column(Text(), nullable=True)
    response = Column(Text(), nullable=True)
    website = Column(String(250), nullable=True)

    service_id = Column(Integer, ForeignKey(Service.id))
    service = relationship(
                    'Service',
                    backref='vulnerabilities_web',
                    )

    __table_args__ = {
        'extend_existing': True
    }

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[1]
    }


class VulnerabilityCode(VulnerabilityGeneric):
    line = Column(Integer, nullable=True)

    source_code_id = Column(Integer, ForeignKey(SourceCode.id), index=True)
    source_code = relationship(
                            SourceCode,
                            backref='vulnerabilities',
                            foreign_keys=[source_code_id]
                            )

    __table_args__ = {
        'extend_existing': True
    }

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[2]
    }


class ReferenceTemplate(db.Model):
    __tablename__ = 'reference_template'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    vulnerability_id = Column(
                            Integer,
                            ForeignKey(VulnerabilityTemplate.id),
                            index=True
                            )
    vulnerability = relationship(
                                'VulnerabilityTemplate',
                                backref='references',
                                foreign_keys=[vulnerability_id],
                                )

    __table_args__ = (
        UniqueConstraint('name', 'vulnerability_id', name='uix_reference_template_name_vulnerability'),
    )


class Reference(db.Model):
    __tablename__ = 'reference'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True,
                        nullable=False
                        )
    workspace = relationship(
                            'Workspace',
                            backref='references',
                            foreign_keys=[workspace_id],
                            )

    vulnerability_id = Column(
                            Integer,
                            ForeignKey(VulnerabilityGeneric.id),
                            index=True
                            )
    vulnerability = relationship(
                                'VulnerabilityGeneric',
                                backref='references',
                                foreign_keys=[vulnerability_id],
                                )

    __table_args__ = (
        UniqueConstraint('name', 'vulnerability_id', 'workspace_id', name='uix_reference_name_vulnerability_workspace'),
    )


class PolicyViolationTemplate(db.Model):
    __tablename__ = 'policy_violation_template'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    vulnerability_id = Column(
                            Integer,
                            ForeignKey(VulnerabilityTemplate.id),
                            index=True
                            )
    vulnerability = relationship(
                                'VulnerabilityTemplate',
                                backref='policy_violations',
                                foreign_keys=[vulnerability_id]
                                )

    __table_args__ = (
        UniqueConstraint(
                        'name',
                        'vulnerability_id',
                        name='uix_policy_violation_template_name_vulnerability'),
    )


class PolicyViolation(db.Model):
    __tablename__ = 'policy_violation'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True,
                        nullable=False
                        )
    workspace = relationship(
                            'Workspace',
                            backref='policy_violations',
                            foreign_keys=[workspace_id],
                            )

    vulnerability_id = Column(
                            Integer,
                            ForeignKey(VulnerabilityGeneric.id),
                            index=True
                            )
    vulnerability = relationship(
                                'VulnerabilityGeneric',
                                backref='policy_violations',
                                foreign_keys=[vulnerability_id]
                                )

    __table_args__ = (
        UniqueConstraint(
                        'name',
                        'vulnerability_id',
                        'workspace_id',
                        name='uix_policy_violation_template_name_vulnerability_workspace'),
    )


class Credential(db.Model):
    # TODO: add unique constraint -> username, host o service y workspace
    # TODO: add constraint host y service, uno o el otro
    __tablename__ = 'credential'
    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    password = Column(Text(), nullable=False)
    description = Column(Text(), nullable=True)
    name = Column(String(250), nullable=True)

    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)
    entity_metadata = relationship(
                                EntityMetadata,
                                uselist=False,
                                cascade="all, delete-orphan",
                                single_parent=True,
                                foreign_keys=[entity_metadata_id],
                                )

    host_id = Column(Integer, ForeignKey(Host.id), index=True, nullable=True)
    host = relationship('Host', backref='credentials', foreign_keys=[host_id])

    service_id = Column(Integer, ForeignKey(Service.id), index=True, nullable=True)
    service = relationship(
                        'Service',
                        backref='credentials',
                        foreign_keys=[service_id],
                        )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
                            'Workspace',
                            backref='credentials',
                            foreign_keys=[workspace_id],
                            )

    __table_args__ = (
        CheckConstraint('(host_id IS NULL AND service_id IS NOT NULL) OR '
                        '(host_id IS NOT NULL AND service_id IS NULL)',
                        name='check_credential_host_service'),
        UniqueConstraint(
                        'username',
                        'host_id',
                        'service_id',
                        'workspace_id',
                        name='uix_credential_username_host_service_workspace'
                        ),
    )


class Command(db.Model):
    __tablename__ = 'command'
    id = Column(Integer, primary_key=True)
    command = Column(Text(), nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=True)
    ip = Column(String(250), nullable=False)  # where the command was executed
    hostname = Column(String(250), nullable=False)  # where the command was executed
    params = Column(Text(), nullable=True)
    user = Column(String(250), nullable=True)  # os username where the command was executed

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', foreign_keys=[workspace_id])
    # TODO: add Tool relationship and report_attachment

    entity_metadata_id = Column(
                                Integer,
                                ForeignKey(EntityMetadata.id),
                                index=True
                                )
    entity_metadata = relationship(
                                EntityMetadata,
                                uselist=False,
                                cascade="all, delete-orphan",
                                single_parent=True,
                                foreign_keys=[entity_metadata_id]
                                )


class Workspace(db.Model):
    __tablename__ = 'workspace'
    id = Column(Integer, primary_key=True)
    # TODO: change nullable=True for appropriate fields
    customer = Column(String(250), nullable=True)  # TBI
    description = Column(Text(), nullable=True)
    active = Column(Boolean(), nullable=False, default=True)  # TBI
    end_date = Column(DateTime(), nullable=True)
    name = Column(String(250), nullable=False, unique=True)
    public = Column(Boolean(), nullable=False, default=True)  # TBI
    scope = Column(Text(), nullable=True)
    start_date = Column(DateTime(), nullable=True)


def is_valid_workspace(workspace_name):
    return db.session.query(server.models.Workspace).filter_by(name=workspace_name).first() is not None


def get(workspace_name):
    return db.session.query(Workspace).filter_by(name=workspace_name).first()


class RolesUsers(db.Model):
    __tablename__ = 'roles_users'
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    role_id = Column('role_id', Integer(), ForeignKey('role.id'))


class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(String(255), nullable=True)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=True)
    email = Column(String(255), unique=True, nullable=True)  # TBI
    name = Column(String(255), nullable=True)  # TBI
    is_ldap = Column(Boolean(), nullable=False, default=False)
    last_login_at = Column(DateTime())  # flask-security
    current_login_at = Column(DateTime())  # flask-security
    last_login_ip = Column(String(100))  # flask-security
    current_login_ip = Column(String(100))  # flask-security
    login_count = Column(Integer)  # flask-security
    active = Column(Boolean(), default=True, nullable=False)  # TBI flask-security
    confirmed_at = Column(DateTime())
    roles = relationship('Role', secondary='roles_users',
                         backref=backref('users', lazy='dynamic'))
    # TODO: add  many to many relationship to add permission to workspace

    @property
    def role(self):
        """ "admin", "pentester", "client" or None """
        try:
            return next(role_name for role_name
                        in ['admin', 'pentester', 'client']
                        if self.has_role(role_name))
        except StopIteration:
            return None

    def get_security_payload(self):
        return {
            "username": self.username,
            "role": self.role,
            "roles": [role.name for role in self.roles],  # Deprectated
            "name": self.email
        }

    def __repr__(self):
        return '<%sUser: %s>' % ('LDAP ' if self.is_ldap else '',
                                 self.username)


class MethodologyTemplate(db.Model):
    # TODO: reset template_id in methodologies when deleting meth template
    __tablename__ = 'methodology_template'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)


class Methodology(db.Model):
    # TODO: add unique constraint -> name, workspace
    __tablename__ = 'methodology'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    entity_metadata_id = Column(
                            Integer,
                            ForeignKey(EntityMetadata.id),
                            index=True
                            )
    entity_metadata = relationship(
                                EntityMetadata,
                                uselist=False,
                                cascade="all, delete-orphan",
                                single_parent=True,
                                foreign_keys=[entity_metadata_id]
                                )

    template = relationship('MethodologyTemplate', backref='methodologies')
    template_id = Column(
                    Integer,
                    ForeignKey('methodology_template.id'),
                    index=True,
                    nullable=True,
                    )

    workspace = relationship('Workspace', backref='methodologies')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)


class TaskABC(db.Model):
    __abstract__ = True

    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=False)


class TaskTemplate(TaskABC):
    __tablename__ = 'task_template'
    id = Column(Integer, primary_key=True)

    __mapper_args__ = {
        'concrete': True
    }

    template = relationship('MethodologyTemplate', backref='tasks')
    template_id = Column(
                    Integer,
                    ForeignKey('methodology_template.id'),
                    index=True,
                    nullable=False,
                    )

    # __table_args__ = (
    #     UniqueConstraint(template_id, name='uix_task_template_name_desc_template_delete'),
    # )


class Task(TaskABC):
    STATUSES = [
        'new',
        'in progress',
        'review',
        'completed',
    ]

    __tablename__ = 'task'
    id = Column(Integer, primary_key=True)

    due_date = Column(DateTime, nullable=True)
    status = Column(Enum(*STATUSES, name='task_statuses'), nullable=True)

    __mapper_args__ = {
        'concrete': True
    }

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    assigned_to = relationship('User', backref='assigned_tasks')
    assigned_to_id = Column(Integer, ForeignKey('user.id'), nullable=True)

    methodology_id = Column(
                    Integer,
                    ForeignKey('methodology.id'),
                    index=True,
                    nullable=False,
                    )
    methodology = relationship('Methodology', backref='tasks')

    template_id = Column(
                    Integer,
                    ForeignKey('task_template.id'),
                    index=True,
                    nullable=True,
                    )
    template = relationship('TaskTemplate', backref='tasks')

    workspace = relationship('Workspace', backref='tasks')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)

    # __table_args__ = (
    #     UniqueConstraint(TaskABC.name, methodology_id, workspace_id, name='uix_task_name_desc_methodology_workspace'),
    # )


class License(db.Model):
    __tablename__ = 'license'
    id = Column(Integer, primary_key=True)
    product = Column(Text, nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)

    type = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint('product', 'start_date', 'end_date', name='uix_license_product_start_end_dates'),
    )


class Tag(db.Model):
    __tablename__ = 'tag'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=True)
    slug = Column(Text, nullable=False, unique=True)


class TagObject(db.Model):
    __tablename__ = 'tag_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Text, nullable=False)

    tag = relationship('Tag', backref='tagged_objects')
    tag_id = Column(Integer, ForeignKey('tag.id'), index=True)


class Comment(db.Model):
    __tablename__ = 'comment'
    id = Column(Integer, primary_key=True)

    text = Column(Text, nullable=False)

    reply_to_id = Column(Integer, ForeignKey('comment.id'))
    reply_to = relationship(
                        'Comment',
                        remote_side=[id],
                        foreign_keys=[reply_to_id]
                        )

    object_id = Column(Integer, nullable=False)
    object_type = Column(Text, nullable=False)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', foreign_keys=[workspace_id])

class ExecutiveReport(db.Model):
    STATUSES = [
        'created',
        'error',
        'processing',
    ]
    __tablename__ = 'executive_report'
    id = Column(Integer, primary_key=True)

    grouped = Column(Boolean, nullable=False, default=False)
    name = Column(Text, nullable=False, index=True)
    status = Column(Enum(*STATUSES, name='executive_report_statuses'), nullable=True)
    template_name = Column(Text, nullable=False)

    conclusions = Column(Text, nullable=True)
    enterprise = Column(Text, nullable=True)
    objectives = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)
    scope = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    title = Column(Text, nullable=True)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', foreign_keys=[workspace_id])


# This constraint uses Columns from different classes
# Since it applies to the table vulnerability it should be adVulnerability.ded to the Vulnerability class
# However, since it contains columns from children classes, this cannot be done
# This is a workaround suggested by SQLAlchemy's creator
CheckConstraint('((Vulnerability.host_id IS NOT NULL)::int+'
                '(Vulnerability.service_id IS NOT NULL)::int+'
                '(Vulnerability.source_code_id IS NOT NULL)::int)=1',
                name='check_vulnerability_host_service_source_code',
                table=VulnerabilityGeneric.__table__)
UniqueConstraint(VulnerabilityGeneric.name,
                 VulnerabilityGeneric.severity,
                 Vulnerability.host_id,
                 VulnerabilityWeb.service_id,
                 VulnerabilityWeb.method,
                 VulnerabilityWeb.parameter_name,
                 VulnerabilityWeb.path,
                 VulnerabilityWeb.website,
                 VulnerabilityGeneric.workspace_id,
                 VulnerabilityCode.source_code_id,
                 name='uix_vulnerability'
)