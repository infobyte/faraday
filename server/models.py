# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    Float,
    Text,
    UniqueConstraint,
    DateTime
)
from sqlalchemy.orm import relationship, backref
from flask_sqlalchemy import SQLAlchemy
from flask_security import (
    UserMixin,
    RoleMixin,
)

import server.config

db = SQLAlchemy()


SCHEMA_VERSION = 'W.2.6.3'


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


class Host(db.Model):
    __tablename__ = 'host'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(Text(), nullable=False)
    os = Column(String(250), nullable=False)

    owned = Column(Boolean)

    default_gateway_ip = Column(String(250))
    default_gateway_mac = Column(String(250))

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    interfaces = relationship('Interface')
    services = relationship('Service')
    vulnerabilities = relationship('Vulnerability')
    credentials = relationship('Credential')

    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Interface(db.Model):
    __tablename__ = 'interface'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String(250), nullable=False)
    mac = Column(String(250), nullable=False)
    owned = Column(Boolean)

    hostnames = Column(String(250))
    network_segment = Column(String(250))

    ipv4_address = Column(String(250))
    ipv4_gateway = Column(String(250))
    ipv4_dns = Column(String(250))
    ipv4_mask = Column(String(250))

    ipv6_address = Column(String(250))
    ipv6_gateway = Column(String(250))
    ipv6_dns = Column(String(250))
    ipv6_prefix = Column(String(250))

    ports_filtered = Column(Integer)
    ports_opened = Column(Integer)
    ports_closed = Column(Integer)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship('Host', back_populates='interfaces')
    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)

    services = relationship('Service')


class Service(db.Model):
    # Table schema
    __tablename__ = 'service'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String(250), nullable=False)
    ports = Column(String(250), nullable=False)
    owned = Column(Boolean)

    protocol = Column(String(250))
    status = Column(String(250))
    version = Column(String(250))

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship('Host', back_populates='services')

    interface_id = Column(Integer, ForeignKey(Interface.id), index=True)
    interface = relationship('Interface', back_populates='services')

    vulnerabilities = relationship('Vulnerability')
    credentials = relationship('Credential')
    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Vulnerability(db.Model):
    __tablename__ = 'vulnerability'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(Text(), nullable=False)

    confirmed = Column(Boolean)
    vuln_type = Column(String(250))
    data = Column(Text())
    easeofresolution = Column(String(50))
    refs = Column(Text())
    resolution = Column(Text())
    severity = Column(String(50))
    owned = Column(Boolean)
    attachments = Column(Text(), nullable=True)
    policyviolations = Column(Text())

    impact_accountability = Column(Boolean)
    impact_availability = Column(Boolean)
    impact_confidentiality = Column(Boolean)
    impact_integrity = Column(Boolean)

    method = Column(String(50))
    params = Column(String(500))
    path = Column(String(500))
    pname = Column(String(250))
    query = Column(Text())
    request = Column(Text())
    response = Column(Text())
    website = Column(String(250))

    status = Column(String(250))

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship('Host', back_populates='vulnerabilities')

    service_id = Column(Integer, ForeignKey(Service.id), index=True)
    service = relationship('Service', back_populates='vulnerabilities')

    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Note(db.Model):
    __tablename__ = 'note'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    text = Column(Text(), nullable=True)
    description = Column(Text(), nullable=True)
    owned = Column(Boolean)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)
    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Credential(db.Model):
    __tablename__ = 'credential'
    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    password = Column(Text(), nullable=False)
    owned = Column(Boolean)
    description = Column(Text(), nullable=True)
    name = Column(String(250), nullable=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship('Host', back_populates='credentials')

    service_id = Column(Integer, ForeignKey(Service.id), index=True)
    service = relationship('Service', back_populates='credentials')
    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)


class Command(db.Model):
    __tablename__ = 'command'
    id = Column(Integer, primary_key=True)
    command = Column(String(250), nullable=True)
    duration = Column(Float, nullable=True)
    itime = Column(Float, nullable=True)
    ip = Column(String(250), nullable=True)
    hostname = Column(String(250), nullable=True)
    params = Column(String(250), nullable=True)
    user = Column(String(250), nullable=True)
    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)


class Workspace(db.Model):
    __tablename__ = 'workspace'
    id = Column(Integer, primary_key=True)
    # TODO: change nullable=True for appropriate fields
    create_date = Column(DateTime(), nullable=True)
    creator = Column(Integer(), nullable=True)
    customer = Column(String(250), nullable=True)
    description = Column(Text(), nullable=True)
    disabled = Column(Boolean(), nullable=True)
    end_date = Column(DateTime(), nullable=True)
    name = Column(String(250), nullable=True, unique=True)
    public = Column(Boolean(), nullable=True)
    scope = Column(Text(), nullable=True)
    start_date = Column(DateTime(), nullable=True)
    update_date = Column(DateTime(), nullable=True)


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
