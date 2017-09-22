# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from datetime import datetime

import pytz
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    event,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event
)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import select, text, table, column
from sqlalchemy import func
from sqlalchemy.orm import column_property
from sqlalchemy.schema import DDL
from sqlalchemy.ext.declarative import declared_attr
from flask_sqlalchemy import (
    SQLAlchemy as OriginalSQLAlchemy,
    _EngineConnector
)
from flask_security import (
    RoleMixin,
    UserMixin,
)

import server.config


class SQLAlchemy(OriginalSQLAlchemy):
    """Override to fix issues when doing a rollback with sqlite driver
    See http://docs.sqlalchemy.org/en/rel_1_0/dialects/sqlite.html#serializable-isolation-savepoints-transactional-ddl
    and https://bitbucket.org/zzzeek/sqlalchemy/issues/3561/sqlite-nested-transactions-fail-with
    for furhter information"""

    def make_connector(self, app=None, bind=None):
        """Creates the connector for a given state and bind."""
        return CustomEngineConnector(self, self.get_app(app), bind)


class CustomEngineConnector(_EngineConnector):
        """Used by overrided SQLAlchemy class to fix rollback issues.

        Also set case sensitive likes (in SQLite there are case
        insensitive by default)"""

        def get_engine(self):
            # Use an existent engine and don't register events if possible
            uri = self.get_uri()
            echo = self._app.config['SQLALCHEMY_ECHO']
            if (uri, echo) == self._connected_for:
                return self._engine

            # Call original metohd and register events
            rv = super(CustomEngineConnector, self).get_engine()
            if uri.startswith('sqlite://'):
                with self._lock:
                    @event.listens_for(rv, "connect")
                    def do_connect(dbapi_connection, connection_record):
                        # disable pysqlite's emitting of the BEGIN statement
                        # entirely.  also stops it from emitting COMMIT before any
                        # DDL.
                        dbapi_connection.isolation_level = None
                        cursor = dbapi_connection.cursor()
                        cursor.execute("PRAGMA case_sensitive_like=true")
                        cursor.close()

                    @event.listens_for(rv, "begin")
                    def do_begin(conn):
                        # emit our own BEGIN
                        conn.execute("BEGIN")
            return rv


db = SQLAlchemy()

SCHEMA_VERSION = 'W.3.0.0'


def _make_generic_count_property(parent_table, children_table):
    """Make a deferred by default column property that counts the
    amount of childrens of some parent object"""
    # TODO: Fix SQLAlchemy warnings
    children_id_field = '{}.id'.format(children_table)
    parent_id_field = '{}.id'.format(parent_table)
    children_rel_field = '{}.{}_id'.format(children_table, parent_table)
    query = (select([func.count(column(children_id_field))]).
             select_from(table(children_table)).
             where(text('{} = {}'.format(
                 children_rel_field, parent_id_field))))
    return column_property(query, deferred=True)


class DatabaseMetadata(db.Model):
    __tablename__ = 'db_metadata'
    id = Column(Integer, primary_key=True)
    option = Column(String(250), nullable=False)
    value = Column(String(250), nullable=False)


class Metadata(db.Model):

    __abstract__ = True

    @declared_attr
    def creator_id(cls):
        return Column(Integer, ForeignKey('user.id'), nullable=True)

    @declared_attr
    def creator(cls):
        return relationship('User', foreign_keys=[cls.creator_id])

    create_date = Column(DateTime, default=datetime.utcnow)
    update_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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


class SourceCode(Metadata):
    __tablename__ = 'source_code'
    id = Column(Integer, primary_key=True)
    filename = Column(Text, nullable=False)
    function = Column(Text, nullable=True)
    module = Column(Text, nullable=True)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', backref='source_codes')

    __table_args__ = (
        UniqueConstraint(filename, workspace_id, name='uix_source_code_filename_workspace'),
    )


class Host(Metadata):
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

    service_count = _make_generic_count_property('host', 'service')

    __table_args__ = (
        UniqueConstraint(ip, workspace_id, name='uix_host_ip_workspace'),
    )


class Hostname(Metadata):
    __tablename__ = 'hostname'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    host_id = Column(Integer, ForeignKey('host.id'), index=True, nullable=False)
    host = relationship('Host', backref='hostnames')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref='hostnames',
        foreign_keys=[workspace_id]
    )
    __table_args__ = (
        UniqueConstraint(name, host_id, workspace_id, name='uix_hostname_host_workspace'),
    )


class Service(Metadata):
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
    status = Column(Enum(*STATUSES, name='service_statuses'), nullable=False)
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


class VulnerabilityABC(Metadata):
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
    risk = Column(Float(3,1), nullable=True)
    # TODO add evidence

    impact_accountability = Column(Boolean, default=False)
    impact_availability = Column(Boolean, default=False)
    impact_confidentiality = Column(Boolean, default=False)
    impact_integrity = Column(Boolean, default=False)

    __table_args__ = (
        CheckConstraint('1.0 <= risk AND risk <= 10.0',
                        name='check_vulnerability_risk'),
    )


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
    __tablename__ = None
    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship(
                    'Host',
                    backref='vulnerabilities',
                    foreign_keys=[host_id],
                    )

    @declared_attr
    def service_id(cls):
        return VulnerabilityGeneric.__table__.c.get('service_id', Column(Integer, db.ForeignKey('service.id')))

    @declared_attr
    def service(cls):
        return relationship('Service')

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[0]
    }


class VulnerabilityWeb(VulnerabilityGeneric):
    __tablename__ = None
    method = Column(String(50), nullable=True)
    parameters = Column(String(500), nullable=True)
    parameter_name = Column(String(250), nullable=True)
    path = Column(String(500), nullable=True)
    query = Column(Text(), nullable=True)
    request = Column(Text(), nullable=True)
    response = Column(Text(), nullable=True)
    website = Column(String(250), nullable=True)

    @declared_attr
    def service_id(cls):
        return VulnerabilityGeneric.__table__.c.get('service_id', Column(Integer, db.ForeignKey('service.id')))

    @declared_attr
    def service(cls):
        return relationship('Service')

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[1]
    }


class VulnerabilityCode(VulnerabilityGeneric):
    __tablename__ = None
    code = Column(Text, nullable=True)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)

    source_code_id = Column(Integer, ForeignKey(SourceCode.id), index=True)
    source_code = relationship(
                            SourceCode,
                            backref='vulnerabilities',
                            foreign_keys=[source_code_id]
                            )

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[2]
    }


class ReferenceTemplate(Metadata):
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


class Reference(Metadata):
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


class PolicyViolationTemplate(Metadata):
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


class PolicyViolation(Metadata):
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


class Credential(Metadata):
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


class Command(Metadata):
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


def _make_vuln_count_property(type_=None):
    query = (select([func.count(column('vulnerability.id'))]).
             select_from(table('vulnerability')).
             where(text('vulnerability.workspace_id = workspace.id'))
             )
    if type_:
        # Don't do queries using this style!
        # This can cause SQL injection vulnerabilities
        # In this case type_ is supplied from a whitelist so this is safe
        query = query.where(text("vulnerability.type = '%s'" % type_))
    return column_property(query, deferred=True)


class Workspace(Metadata):
    __tablename__ = 'workspace'
    id = Column(Integer, primary_key=True)
    customer = Column(String(250), nullable=True)  # TBI
    description = Column(Text(), nullable=True)
    active = Column(Boolean(), nullable=False, default=True)  # TBI
    end_date = Column(DateTime(), nullable=True)
    name = Column(String(250), nullable=False, unique=True)
    public = Column(Boolean(), nullable=False, default=True)  # TBI
    start_date = Column(DateTime(), nullable=True)

    credential_count = _make_generic_count_property('workspace', 'credential')
    host_count = _make_generic_count_property('workspace', 'host')
    service_count = _make_generic_count_property('workspace', 'service')
    vulnerability_web_count = _make_vuln_count_property('vulnerability_web')
    vulnerability_code_count = _make_vuln_count_property('vulnerability_code')
    vulnerability_standard_count = _make_vuln_count_property('vulnerability')
    vulnerability_total_count = _make_vuln_count_property()


class Scope(Metadata):
    __tablename__ = 'scope'
    id = Column(Integer, primary_key=True)
    name = Column(Text(), nullable=False)

    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True,
                        nullable=False
                        )
    workspace = relationship(
                            'Workspace',
                            backref='scope',
                            foreign_keys=[workspace_id],
                            )

    __table_args__ = (
        UniqueConstraint('name', 'workspace_id', name='uix_scope_name_workspace'),
    )

def is_valid_workspace(workspace_name):
    return db.session.query(server.models.Workspace).filter_by(name=workspace_name).first() is not None


def get(workspace_name):
    return db.session.query(Workspace).filter_by(name=workspace_name).first()


class RolesUsers(db.Model):
    __tablename__ = 'roles_users'
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    role_id = Column('role_id', Integer(), ForeignKey('role.id'))


class Role(Metadata, RoleMixin):
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


class MethodologyTemplate(Metadata):
    # TODO: reset template_id in methodologies when deleting meth template
    __tablename__ = 'methodology_template'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)


class Methodology(Metadata):
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


class TaskABC(Metadata):
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

    assigned_to_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    assigned_to = relationship('User', backref='assigned_tasks', foreign_keys=[assigned_to_id])

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


class License(Metadata):
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


class Tag(Metadata):
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


class CommentObject(db.Model):
    __tablename__ = 'comment_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Text, nullable=False)

    comment = relationship('Comment', backref='comment_objects')
    comment_id = Column(Integer, ForeignKey('comment.id'), index=True)


class Comment(Metadata):
    __tablename__ = 'comment'
    id = Column(Integer, primary_key=True)

    text = Column(Text, nullable=False)

    reply_to_id = Column(Integer, ForeignKey('comment.id'))
    reply_to = relationship(
                        'Comment',
                        remote_side=[id],
                        foreign_keys=[reply_to_id]
                        )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', foreign_keys=[workspace_id])


class ExecutiveReport(Metadata):
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

vulnerability_uniqueness = DDL(
    "CREATE UNIQUE INDEX uix_vulnerability ON %(fullname)s "
    "(name, md5(description), severity, host_id, service_id, "
    "method, parameter_name, path, website, workspace_id, source_code_id);"
)

event.listen(
    VulnerabilityGeneric.__table__,
    'after_create',
    vulnerability_uniqueness.execute_if(dialect='postgresql')
)
