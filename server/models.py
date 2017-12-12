# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from datetime import datetime

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
    event,
    and_)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import backref, relationship, undefer
from sqlalchemy.sql import select, text, table
from sqlalchemy import func
from sqlalchemy.orm import (
    backref,
    column_property,
    query_expression,
    with_expression
)
from sqlalchemy.schema import DDL
from sqlalchemy.ext.associationproxy import association_proxy, _AssociationSet
from sqlalchemy.ext.declarative import declared_attr
from flask_sqlalchemy import (
    SQLAlchemy as OriginalSQLAlchemy,
    _EngineConnector
)
from depot.fields.sqlalchemy import UploadedFileField

import server.config
from server.fields import FaradayUploadedFile
from flask_security import (
    RoleMixin,
    UserMixin,
)
from server.utils.database import get_or_create, BooleanToIntColumn


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


def _make_generic_count_property(parent_table, children_table, where=None):
    """Make a deferred by default column property that counts the
    amount of childrens of some parent object"""
    children_id_field = '{}.id'.format(children_table)
    parent_id_field = '{}.id'.format(parent_table)
    children_rel_field = '{}.{}_id'.format(children_table, parent_table)
    query = (select([func.count(text(children_id_field))]).
             select_from(table(children_table)).
             where(text('{} = {}'.format(
                 children_rel_field, parent_id_field))))
    if where is not None:
        query = query.where(where)
    return column_property(query, deferred=True)


def _make_command_created_related_object():
    query = select([BooleanToIntColumn("(count(*) = 0)")])
    query = query.select_from(text('command_object as command_object_inner'))
    where_expr = " command_object_inner.create_date < command_object.create_date and " \
                " (command_object_inner.object_id = command_object.object_id and " \
                " command_object_inner.object_type = command_object.object_type) and " \
                " command_object_inner.workspace_id = command_object.workspace_id "
    query = query.where(text(where_expr))
    return column_property(
        query,
    )


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

    @property
    def parent(self):
        return


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

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True,
                          nullable=False)
    workspace = relationship(
                            'Workspace',
                            backref='hosts',
                            foreign_keys=[workspace_id]
                            )

    open_service_count = _make_generic_count_property(
        'host', 'service', where=text("service.status = 'open'"))
    total_service_count = _make_generic_count_property('host', 'service')

    __host_vulnerabilities = (
        select([func.count(text('vulnerability.id'))]).
        select_from('vulnerability').
        where(text('vulnerability.host_id = host.id')).
        as_scalar()
    )
    __service_vulnerabilities = (
        select([func.count(text('vulnerability.id'))]).
        select_from(text('vulnerability, service')).
        where(text('vulnerability.service_id = service.id and '
                   'service.host_id = host.id')).
        as_scalar()
    )
    vulnerability_count = column_property(
        # select(text('count(*)')).select_from(__host_vulnerabilities.subquery()),
        __host_vulnerabilities + __service_vulnerabilities,
        deferred=True)

    credentials_count = _make_generic_count_property('host', 'credential')

    __table_args__ = (
        UniqueConstraint(ip, workspace_id, name='uix_host_ip_workspace'),
    )

    @property
    def parent(self):
        return


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

    def __str__(self):
        return self.name

    @property
    def parent(self):
        return self.host


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

    host_id = Column(Integer, ForeignKey('host.id'), index=True, nullable=False)
    host = relationship('Host', backref='services', foreign_keys=[host_id])

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
                            'Workspace',
                            backref='services',
                            foreign_keys=[workspace_id]
                            )

    vulnerability_count = _make_generic_count_property('service',
                                                       'vulnerability')
    credentials_count = _make_generic_count_property('service', 'credential')

    __table_args__ = (
        UniqueConstraint(port, protocol, host_id, workspace_id, name='uix_service_port_protocol_host_workspace'),
    )

    @property
    def parent(self):
        return self.host


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

    @property
    def parent(self):
        raise NotImplementedError('ABC property called')


class CustomAssociationSet(_AssociationSet):
    """
    A custom associacion set that passes the creator method the both
    the value and the instance of the parent object
    """

    # def __init__(self, lazy_collection, creator, getter, setter, parent):
    def __init__(self, lazy_collection, creator, value_attr, parent):
        """I have to override this method because the proxy_factory
        class takes different arguments than the hardcoded
        _AssociationSet one.
        In particular, the getter and the setter aren't passed, but
        since I have an instance of the parent (AssociationProxy
        instance) I do the logic here.
        The value_attr argument isn't relevant to this implementation
        """

        if parent.getset_factory:
            getter, setter = parent.getset_factory(
                parent.collection_class, parent)
        else:
            getter, setter = parent._default_getset(parent.collection_class)

        super(CustomAssociationSet, self).__init__(
            lazy_collection, creator, getter, setter, parent)

    def _create(self, value):
        parent_instance = self.lazy_collection.ref()
        return self.creator(value, parent_instance)


def _build_associationproxy_creator(model_class_name):
    def creator(name, vulnerability):
        """Get or create a reference/policyviolation with the
        corresponding name. This must be worspace aware"""

        # Ugly hack to avoid the fact that Reference is defined after
        # Vulnerability
        model_class = globals()[model_class_name]

        assert (vulnerability.workspace and vulnerability.workspace.id
                is not None), "Unknown workspace id"
        child = model_class.query.filter(
            getattr(model_class, 'workspace') == vulnerability.workspace,
            getattr(model_class, 'name') == name,
        ).first()
        if child is None:
            # Doesn't exist
            child = model_class(name, vulnerability.workspace.id)
        return child

    return creator


def _build_associationproxy_creator_non_workspaced(model_class_name):
    def creator(name, vulnerability):
        """Get or create a reference/policyviolation with the
        corresponding name. This must be worspace aware"""

        # Ugly hack to avoid the fact that Reference is defined after
        # Vulnerability
        model_class = globals()[model_class_name]
        child = model_class.query.filter(
            getattr(model_class, 'name') == name,
        ).first()
        if child is None:
            # Doesn't exist
            child = model_class(name)
        return child

    return creator


class VulnerabilityTemplate(VulnerabilityABC):
    __tablename__ = 'vulnerability_template'

    __table_args__ = (
        UniqueConstraint('name', name='uix_vulnerability_template_name'),
    )

    # We use ReferenceTemplate and not Reference since Templates does not have workspace.

    reference_template_instances = relationship(
        "ReferenceTemplate",
        secondary="reference_template_vulnerability_association",
        lazy="joined",
        collection_class=set
    )

    references = association_proxy(
        'reference_template_instances', 'name',
        proxy_factory=CustomAssociationSet,
        creator=_build_associationproxy_creator_non_workspaced('ReferenceTemplate')
    )

    policy_violation_template_instances = relationship(
        "PolicyViolationTemplate",
        secondary="policy_violation_template_vulnerability_association",
        lazy="joined",
        collection_class=set
    )

    policy_violations = association_proxy(
        'policy_violation_template_instances', 'name',
        proxy_factory=CustomAssociationSet,
        creator=_build_associationproxy_creator_non_workspaced('PolicyViolationTemplate')
    )


class CommandObject(db.Model):
    __tablename__ = 'command_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Text, nullable=False)

    command = relationship('Command', backref='command_objects')
    command_id = Column(Integer, ForeignKey('command.id'), index=True)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', foreign_keys=[workspace_id])

    create_date = Column(DateTime, default=datetime.utcnow)

    # the following properties are used to know if the command created the specified objects_type
    # remeber that this table has a row instances per relationship.
    # this created integer can be used to obtain the total object_type objects created.
    created = _make_command_created_related_object()

    # We are currently using the column property created. however to avoid losing information
    # we also store the a boolean to know if at the moment of created the object related to the
    # Command was created.
    created_persistent = Column(Boolean, default=False)

    __table_args__ = (
        UniqueConstraint('object_id', 'object_type', 'command_id', 'workspace_id',
                         name='uix_command_object_object_id_object_type_command_id_workspace_id'),
    )

    @property
    def parent(self):
        return self.command


def _make_created_objects_sum(object_type_filter):
    where_conditions = ["command_object.object_type= '%s'" % object_type_filter]
    where_conditions.append("command_object.command_id = command.id")
    where_conditions.append("command_object.workspace_id = command.workspace_id")
    return column_property(
        select([func.sum(CommandObject.created)]).\
        select_from(table('command_object')). \
        where(text(' and '.join(where_conditions)))
    )


def _make_created_objects_sum_joined(object_type_filter, join_filters):
    """

    :param object_type_filter: can be any host, service, vulnerability, credential or any object created from commands.
    :param join_filters: Filter for vulnerability fields.
    :return: column property with sum of created objects.
    """
    where_conditions = ["command_object.object_type= '%s'" % object_type_filter]
    where_conditions.append("command_object.command_id = command.id")
    where_conditions.append("vulnerability.id = command_object.object_id ")
    where_conditions.append("command_object.workspace_id = vulnerability.workspace_id")
    for attr, filter_value in join_filters.items():
        where_conditions.append("vulnerability.{0} = {1}".format(attr, filter_value))
    return column_property(
        select([func.sum(CommandObject.created)]). \
            select_from(table('command_object')). \
            select_from(table('vulnerability')). \
            where(text(' and '.join(where_conditions)))
    )


class Command(Metadata):

    IMPORT_SOURCE = [
        'report',  # all the files the tools export and faraday imports it from the resports directory, gtk manual import or web import.
        'shell',  # command executed on the shell or webshell with hooks connected to faraday.
    ]

    __tablename__ = 'command'
    id = Column(Integer, primary_key=True)
    command = Column(Text(), nullable=False)
    tool = Column(Text(), nullable=False, default='')
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=True)
    ip = Column(String(250), nullable=False)  # where the command was executed
    hostname = Column(String(250), nullable=False)  # where the command was executed
    params = Column(Text(), nullable=True)
    user = Column(String(250), nullable=True)  # os username where the command was executed
    import_source = Column(Enum(*IMPORT_SOURCE, name='import_source_enum'))

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', foreign_keys=[workspace_id])
    # TODO: add Tool relationship and report_attachment

    sum_created_vulnerabilities = _make_created_objects_sum('vulnerability')

    sum_created_vulnerabilities_web = _make_created_objects_sum_joined('vulnerability', {'type': '\'vulnerability_web\''})

    sum_created_hosts = _make_created_objects_sum('host')

    sum_created_services = _make_created_objects_sum('service')

    sum_created_vulnerability_critical = _make_created_objects_sum_joined('vulnerability', {'severity': '\'critical\''})

    @property
    def parent(self):
        return


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

    reference_instances = relationship(
        "Reference",
        secondary="reference_vulnerability_association",
        lazy="joined",
        collection_class=set
    )

    references = association_proxy(
        'reference_instances', 'name',
        proxy_factory=CustomAssociationSet,
        creator=_build_associationproxy_creator('Reference'))

    policy_violation_instances = relationship(
        "PolicyViolation",
        secondary="policy_violation_vulnerability_association",
        lazy="joined",
        collection_class=set
    )

    policy_violations = association_proxy(
        'policy_violation_instances', 'name',
        proxy_factory=CustomAssociationSet,
        creator=_build_associationproxy_creator('PolicyViolation'))

    evidence = relationship(
        "File",
        primaryjoin="and_(File.object_id==VulnerabilityGeneric.id, "
                    "File.object_type=='vulnerability')",
        foreign_keys="File.object_id",
    )

    tags = relationship(
        "Tag",
        secondary="tag_object",
        primaryjoin="and_(TagObject.object_id==VulnerabilityGeneric.id, "
                    "TagObject.object_type=='vulnerability')",
        collection_class=set,
    )

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
        return relationship('Service', backref='vulnerabilities')

    @property
    def hostnames(self):
        if self.host is not None:
            return self.host.hostnames
        elif self.service is not None:
            return self.service.host.hostnames
        raise ValueError("Vulnerability has no service nor host")

    @property
    def parent(self):
        return self.host or self.service

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[0]
    }


class VulnerabilityWeb(VulnerabilityGeneric):
    __tablename__ = None
    method = Column(Text, nullable=True)
    parameters = Column(Text, nullable=True)
    parameter_name = Column(Text, nullable=True)
    path = Column(Text, nullable=True)
    query_string = Column(Text, nullable=True)
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    website = Column(Text, nullable=True)

    @declared_attr
    def service_id(cls):
        return VulnerabilityGeneric.__table__.c.get(
            'service_id', Column(Integer, db.ForeignKey('service.id'),
                                 nullable=False))

    @declared_attr
    def service(cls):
        return relationship('Service', backref='vulnerabilities_web')

    @property
    def parent(self):
        return self.service

    @property
    def hostnames(self):
        return self.service.host.hostnames

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

    @property
    def hostnames(self):
        return []

    @property
    def parent(self):
        return self.source_code


class ReferenceTemplate(Metadata):
    __tablename__ = 'reference_template'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint('name', name='uix_reference_template_name'),
    )

    def __init__(self, name=None, **kwargs):
        super(ReferenceTemplate, self).__init__(name=name,
                                        **kwargs)


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

    __table_args__ = (
        UniqueConstraint('name', 'workspace_id', name='uix_reference_name_vulnerability_workspace'),
    )

    def __init__(self, name=None, workspace_id=None, **kwargs):
        super(Reference, self).__init__(name=name,
                                        workspace_id=workspace_id,
                                        **kwargs)

    @property
    def parent(self):
        # TODO: fix this propery
        return


class ReferenceVulnerabilityAssociation(db.Model):

    __tablename__ = 'reference_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability.id'), primary_key=True)
    reference_id = Column(Integer, ForeignKey('reference.id'), primary_key=True)

    reference = relationship("Reference", backref="reference_associations", foreign_keys=[reference_id])
    vulnerability = relationship("Vulnerability", backref="reference_vulnerability_associations", foreign_keys=[vulnerability_id])


class PolicyViolationVulnerabilityAssociation(db.Model):

    __tablename__ = 'policy_violation_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability.id'), primary_key=True)
    policy_violation_id = Column(Integer, ForeignKey('policy_violation.id'), primary_key=True)

    policy_violation = relationship("PolicyViolation", backref="policy_violation_associations", foreign_keys=[policy_violation_id])
    vulnerability = relationship("Vulnerability", backref="policy_violationvulnerability_associations",
                                 foreign_keys=[vulnerability_id])


class ReferenceTemplateVulnerabilityAssociation(db.Model):

    __tablename__ = 'reference_template_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability_template.id'), primary_key=True)
    reference_id = Column(Integer, ForeignKey('reference_template.id'), primary_key=True)

    reference = relationship("ReferenceTemplate", backref="reference_template_associations", foreign_keys=[reference_id])
    vulnerability = relationship("VulnerabilityTemplate", backref="reference_template_vulnerability_associations", foreign_keys=[vulnerability_id])


class PolicyViolationTemplateVulnerabilityAssociation(db.Model):

    __tablename__ = 'policy_violation_template_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability_template.id'), primary_key=True)
    policy_violation_id = Column(Integer, ForeignKey('policy_violation_template.id'), primary_key=True)

    policy_violation = relationship("PolicyViolationTemplate", backref="policy_violation_template_associations", foreign_keys=[policy_violation_id])
    vulnerability = relationship("VulnerabilityTemplate", backref="policy_violation_template_vulnerability_associations",
                                 foreign_keys=[vulnerability_id])


class PolicyViolationTemplate(Metadata):
    __tablename__ = 'policy_violation_template'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint(
                        'name',
                        name='uix_policy_violation_template_name'),
    )

    def __init__(self, name=None, **kwargs):
        super(PolicyViolationTemplate, self).__init__(name=name,
                                        **kwargs)


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

    __table_args__ = (
        UniqueConstraint(
                        'name',
                        'workspace_id',
                        name='uix_policy_violation_template_name_vulnerability_workspace'),
    )

    def __init__(self, name=None, workspace_id=None, **kwargs):
        super(PolicyViolation, self).__init__(name=name,
                                        workspace_id=workspace_id,
                                        **kwargs)

    @property
    def parent(self):
        # TODO: Fix this property
        return


class Credential(Metadata):
    __tablename__ = 'credential'
    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    password = Column(Text(), nullable=False)
    description = Column(Text(), nullable=True)
    name = Column(String(250), nullable=True)

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

    @property
    def parent(self):
        return self.host or self.service


def _make_vuln_count_property(type_=None, only_confirmed=False,
                              use_column_property=True):
    query = (select([func.count(text('vulnerability.id'))]).
             select_from(table('vulnerability')).
             where(text('vulnerability.workspace_id = workspace.id'))
             )
    if type_:
        # Don't do queries using this style!
        # This can cause SQL injection vulnerabilities
        # In this case type_ is supplied from a whitelist so this is safe
        query = query.where(text("vulnerability.type = '%s'" % type_))
    if only_confirmed:
        if str(db.engine.url).startswith('sqlite://'):
            # SQLite has no "true" expression, we have to use the integer 1
            # instead
            query = query.where(text("vulnerability.confirmed = 1"))
        else:
            # I suppose that we're using PostgreSQL, that can't compare
            # booleans with integers
            query = query.where(text("vulnerability.confirmed = true"))
    if use_column_property:
        return column_property(query, deferred=True)
    else:
        return query


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
    open_service_count = _make_generic_count_property(
        'workspace', 'service', where=text("service.status = 'open'"))
    total_service_count = _make_generic_count_property('workspace', 'service')

    vulnerability_web_count = query_expression()
    vulnerability_code_count = query_expression()
    vulnerability_standard_count = query_expression()
    vulnerability_total_count = query_expression()

    @classmethod
    def query_with_count(cls, only_confirmed):
        """
        Add count fields to the query.

        If only_confirmed is True, it will only show the count for confirmed
        vulnerabilities. Otherwise, it will show the count of all of them
        """
        return cls.query.options(
            undefer(cls.host_count),
            undefer(cls.credential_count),
            undefer(cls.open_service_count),
            undefer(cls.total_service_count),
            with_expression(
                cls.vulnerability_web_count,
                _make_vuln_count_property('vulnerability_web',
                                          only_confirmed=only_confirmed,
                                          use_column_property=False)
            ),
            with_expression(
                cls.vulnerability_code_count,
                _make_vuln_count_property('vulnerability_code',
                                          only_confirmed=only_confirmed,
                                          use_column_property=False)
            ),
            with_expression(
                cls.vulnerability_standard_count,
                _make_vuln_count_property('vulnerability',
                                          only_confirmed=only_confirmed,
                                          use_column_property=False)
            ),
            with_expression(
                cls.vulnerability_total_count,
                _make_vuln_count_property(type_=None,
                                          only_confirmed=only_confirmed,
                                          use_column_property=False)
            ),
        )


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
    workspace = relationship('Workspace',
                             backref=backref('scope', lazy="joined"),
                             foreign_keys=[workspace_id],
                             )

    __table_args__ = (
        UniqueConstraint('name', 'workspace_id',
                         name='uix_scope_name_workspace'),
    )

    @property
    def parent(self):
        return


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


class File(Metadata):
    __tablename__ = 'file'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(Text)
    filename = Column(Text, nullable=False)
    description = Column(Text)
    content = Column(UploadedFileField(upload_type=FaradayUploadedFile),
                     nullable=False)  # plain attached file
    object_id = Column(Integer, nullable=False)
    object_type = Column(Text, nullable=False)


class UserAvatar(Metadata):
    __tablename_ = 'user_avatar'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(Text, unique=True)
    # photo field will automatically generate thumbnail
    # if the file is a valid image
    photo = Column(UploadedFileField(upload_type=FaradayUploadedFile))
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    user = relationship('User', foreign_keys=[user_id])


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

    template = relationship('MethodologyTemplate', backref='methodologies')
    template_id = Column(
                    Integer,
                    ForeignKey('methodology_template.id'),
                    index=True,
                    nullable=True,
                    )

    workspace = relationship('Workspace', backref='methodologies')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)

    @property
    def parent(self):
        return


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

    @property
    def parent(self):
        return self.methodology


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

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True,
                          nullable=False)
    workspace = relationship('Workspace', foreign_keys=[workspace_id])

    object_id = Column(Integer, nullable=False)
    object_type = Column(Text, nullable=False)

    @property
    def parent(self):
        return


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

    @property
    def parent(self):
        return


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


def log_command_object_found(command, object, created):
    object_type = object.__tablename__
    if object.__class__.__name__ in ['Vulnerability', 'VulnerabilityWeb', 'VulnerabilityCode']:
        object_type = 'vulnerability'

    db.session.flush()
    log, log_created = get_or_create(
        db.session,
        CommandObject,
        command=command,
        object_id=object.id,
        object_type=object_type,
        workspace=object.workspace,
    )
    if not log_created:
        # without this if, multiple executions of the importer will write this attribute with False
        log.created_persistent = created

# We have to import this after all models are defined
import server.events
