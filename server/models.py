# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from sqlalchemy import (
    Boolean,
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
    # TODO: add unique constraint -> filename, workspace
    __tablename__ = 'source_code'
    id = Column(Integer, primary_key=True)
    filename = Column(Text, nullable=False)

    workspace = relationship('Workspace', backref='source_codes')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Host(db.Model):
    # TODO: add unique constraint -> ip, workspace
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

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    workspace = relationship('Workspace', backref='hosts')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Hostname(db.Model):
    # TODO: add unique constraint -> name, host, workspace
    __tablename__ = 'hostname'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    host = relationship('Host', backref='hostnames')
    host_id = Column(Integer, ForeignKey('host.id'), index=True)


class Service(db.Model):
    # TODO: add unique constraint to -> port, protocol, host_id, workspace
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
    status = Column(Enum(*STATUSES), nullable=True)
    version = Column(Text, nullable=True)

    banner = Column(Text, nullable=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host = relationship('Host', backref='services')
    host_id = Column(Integer, ForeignKey('host.id'), index=True)

    workspace = relationship('Workspace', backref='services')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Reference(db.Model):
    __tablename__ = 'reference'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    workspace = relationship('Workspace', backref='references')
    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True
                        )

    vulnerability = relationship('Vulnerability', backref='references')
    vulnerability_id = Column(
                            Integer,
                            ForeignKey('vulnerbility.id'),
                            index=True
                            )


class PolicyViolation(db.Model):
    __tablename__ = 'policy_violation'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    workspace = relationship('Workspace', backref='policy_violations')
    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True
                        )

    vulnerability = relationship('Vulnerability', backref='policy_violations')
    vulnerability_id = Column(
                            Integer,
                            ForeignKey('vulnerbility.id'),
                            index=True
                            )


class VulnerabilityABC(db.Model):
    # TODO: add unique constraint to -> name, description, severity, parent, method, pname, path, website, workspace
    # revisar plugin nexpose, netspark para terminar de definir uniques. asegurar que se carguen bien
    EASE_OF_RESOLUTIONS = [
        'trivial',
        'simple',
        'moderate',
        'difficult',
        'infeasible'
    ]

    __abstract__ = True
    id = Column(Integer, primary_key=True)

    data = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    ease_of_resolution = Column(Enum(*EASE_OF_RESOLUTIONS), nullable=True)
    name = Column(Text, nullable=False)
    resolution = Column(Text, nullable=True)
    severity = Column(String(50), nullable=False)
    # TODO add evidence

    impact_accountability = Column(Boolean, default=False)
    impact_availability = Column(Boolean, default=False)
    impact_confidentiality = Column(Boolean, default=False)
    impact_integrity = Column(Boolean, default=False)


class VulnerabilityTemplate(VulnerabilityABC):
    __tablename__ = 'vulnerability_template'


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
    status = Column(Enum(*STATUSES), nullable=False, default="open")
    type = Column(Enum(*VULN_TYPES), nullable=False)

    workspace = relationship('Workspace', backref='vulnerabilities')
    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True,
                        )

    __mapper_args__ = {
        'polymorphic_on': type
    }


class Vulnerability(VulnerabilityGeneric):
    id = Column(Integer, primary_key=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host = relationship('Host', backref='vulnerabilities')
    host_id = Column(Integer, ForeignKey(Host.id), index=True)

    service = relationship('Service', backref='vulnerabilities')
    service_id = Column(Integer, ForeignKey(Service.id), index=True)

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[0]
    }


class VulnerabilityWeb(VulnerabilityGeneric):
    id = Column(Integer, primary_key=True)
    method = Column(String(50), nullable=True)
    parameters = Column(String(500), nullable=True)
    parameter_name = Column(String(250), nullable=True)
    path = Column(String(500), nullable=True)
    query = Column(Text(), nullable=True)
    request = Column(Text(), nullable=True)
    response = Column(Text(), nullable=True)
    website = Column(String(250), nullable=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    service = relationship('Service', backref='vulnerabilities')
    service_id = Column(Integer, ForeignKey(Service.id), index=True)

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[1]
    }


class VulnerabilityCode(VulnerabilityGeneric):
    id = Column(Integer, primary_key=True)
    line = Column(Integer, nullable=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    source_code = relationship('SourceCode', backref='vulnerabilities')
    source_code_id = Column(Integer, ForeignKey('SourceCode.id'), index=True)

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[2]
    }


class Credential(db.Model):
    # TODO: add unique constraint -> username, host o service y workspace
    # TODO: add constraint host y service, uno o el otro
    __tablename__ = 'credential'
    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    password = Column(Text(), nullable=False)
    description = Column(Text(), nullable=True)
    name = Column(String(250), nullable=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host = relationship('Host', backref='credentials')
    host_id = Column(Integer, ForeignKey(Host.id), index=True, nullalbe=True)

    service = relationship('Service', backref='credentials')
    service_id = Column(Integer, ForeignKey(Service.id), index=True, nullalbe=True)

    workspace = relationship('Workspace', backref='credentials')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)


class Command(db.Model):
    __tablename__ = 'command'
    id = Column(Integer, primary_key=True)
    command = Column(String(250), nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    ip = Column(String(250), nullable=False)  # where the command was executed
    hostname = Column(String(250), nullable=False)  # where the command was executed
    params = Column(String(250), nullable=True)
    user = Column(String(250), nullable=True)  # where the command was executed
    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)
    # TODO: add Tool relationship and report_attachment

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)


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
    name = Column(String(255), nullalbe=True)  # TBI
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

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    template = relationship('MethodologyTemplate', backref='methodologies')
    template_id = Column(
                    Integer,
                    ForeignKey('methodology_template.id'),
                    index=True,
                    nullable=True,
                    )

    workspace = relationship('Workspace', backref='methodologies')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


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
    status = Column(Enum(*STATUSES), nullable=True)

    __mapper_args__ = {
        'concrete': True
    }

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    assigned_to = relationship('User', backref='assigned_tasks')
    assigned_to_id = Column(Integer, ForeignKey('user.id'), nullable=True)

    methodology = relationship('Methodology', backref='tasks')
    methodology_id = Column(
                    Integer,
                    ForeignKey('methodology.id'),
                    index=True,
                    nullable=False,
                    )

    template = relationship('TaskTemplate', backref='tasks')
    template_id = Column(
                    Integer,
                    ForeignKey('task_template.id'),
                    index=True,
                    nullable=True,
                    )

    workspace = relationship('Workspace', backref='tasks')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class License(db.Model):
    __tablename__ = 'license'
    id = Column(Integer, primary_key=True)
    product = Column(Text, nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)

    type = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)


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

    reply_to = relationship('Comment', backref='replies')
    reply_to_id = Column(Integer, ForeignKey('comment.id'))

    object_id = Column(Integer, nullable=False)
    object_type = Column(Text, nullable=False)

    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)
