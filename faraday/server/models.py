# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import operator
from datetime import datetime
from functools import partial

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
    event,
    text
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship, undefer
from sqlalchemy.sql import select, text, table
from sqlalchemy.sql.expression import asc, case, join
from sqlalchemy.ext.hybrid import hybrid_property
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

import faraday.server.config
from faraday.server.fields import FaradayUploadedFile, JSONType
from flask_security import (
    RoleMixin,
    UserMixin,
)
from faraday.server.utils.database import (
    BooleanToIntColumn,
    get_object_type_for,
    is_unique_constraint_violation)

NonBlankColumn = partial(Column, nullable=False,
                         info={'allow_blank': False})
BlankColumn = partial(Column, nullable=False,
                      info={'allow_blank': True},
                      default='')

OBJECT_TYPES = [
    'vulnerability',
    'host',
    'credential',
    'service',
    'source_code',
    'comment',
    'executive_report',
    'workspace',
    'task'
]


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
        return Column(
            Integer,
            ForeignKey('faraday_user.id', ondelete="SET NULL"),
            nullable=True)

    @declared_attr
    def creator(cls):
        return relationship('User', foreign_keys=[cls.creator_id])

    @declared_attr
    def update_user_id(cls):
        return Column(
            Integer,
            ForeignKey('faraday_user.id', ondelete="SET NULL"),
            nullable=True)

    @declared_attr
    def update_user(cls):
        return relationship('User', foreign_keys=[cls.update_user_id])

    create_date = Column(DateTime, default=datetime.utcnow)
    update_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SourceCode(Metadata):
    __tablename__ = 'source_code'
    id = Column(Integer, primary_key=True)
    filename = NonBlankColumn(Text)
    function = BlankColumn(Text)
    module = BlankColumn(Text)

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
    ip = NonBlankColumn(Text)  # IP v4 or v6
    description = BlankColumn(Text)
    os = BlankColumn(Text)

    owned = Column(Boolean, nullable=False, default=False)

    default_gateway_ip = BlankColumn(Text)
    default_gateway_mac = BlankColumn(Text)

    mac = BlankColumn(Text)
    net_segment = BlankColumn(Text)

    services = relationship(
        'Service',
        order_by='Service.protocol,Service.port',
        cascade="all, delete-orphan"
    )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True,
                          nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref("hosts", cascade="all, delete-orphan")
        )

    open_service_count = _make_generic_count_property(
        'host', 'service', where=text("service.status = 'open'"))
    total_service_count = _make_generic_count_property('host', 'service')

    __host_vulnerabilities = (
        select([func.count(text('vulnerability.id'))]).
        select_from(text('vulnerability')).
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

    vulnerability_info_count = query_expression()
    vulnerability_med_count = query_expression()
    vulnerability_high_count = query_expression()
    vulnerability_critical_count = query_expression()
    vulnerability_low_count = query_expression()
    vulnerability_unclassified_count = query_expression()
    vulnerability_total_count = query_expression()

    @classmethod
    def query_with_count(cls, confirmed, host_ids, workspace_name):
        query = cls.query.join(Workspace).filter(Workspace.name == workspace_name)
        if host_ids:
            query = query.filter(cls.id.in_(host_ids))
        return query.options(
            with_expression(
                cls.vulnerability_info_count,
                _make_vuln_count_property(
                    type_=None,
                    confirmed = confirmed,
                    use_column_property = False,
                    extra_query = "vulnerability.severity='informational'",
                    get_hosts_vulns = True
                )
            ),
            with_expression(
                cls.vulnerability_med_count,
                _make_vuln_count_property(
                    type_ = None,
                    confirmed = confirmed,
                    use_column_property = False,
                    extra_query = "vulnerability.severity='medium'",
                    get_hosts_vulns = True
                )
            ),
            with_expression(
                cls.vulnerability_high_count,
                _make_vuln_count_property(
                    type_ = None,
                    confirmed = confirmed,
                    use_column_property = False,
                    extra_query = "vulnerability.severity='high'",
                    get_hosts_vulns = True
                )
            ),
            with_expression(
                cls.vulnerability_critical_count,
                _make_vuln_count_property(
                    type_ = None,
                    confirmed = confirmed,
                    use_column_property = False,
                    extra_query = "vulnerability.severity='critical'",
                    get_hosts_vulns = True
                )
            ),
            with_expression(
                cls.vulnerability_low_count,
                _make_vuln_count_property(
                    type_ = None,
                    confirmed = confirmed,
                    use_column_property = False,
                    extra_query = "vulnerability.severity='low'",
                    get_hosts_vulns = True
                )
            ),
            with_expression(
                cls.vulnerability_unclassified_count,
                _make_vuln_count_property(
                    type_ = None,
                    confirmed = confirmed,
                    use_column_property = False,
                    extra_query = "vulnerability.severity='unclassified'",
                    get_hosts_vulns = True
                )
            ),
            with_expression(
                cls.vulnerability_total_count,
                _make_vuln_count_property(
                    type_ = None,
                    confirmed = confirmed,
                    use_column_property = False,
                    get_hosts_vulns = True
                )
            ),
        )

    @property
    def parent(self):
        return

    def set_hostnames(self, new_hostnames):
        """Override the host's hostnames. Take care of deleting old not
        used hostnames and to leave the sames the ones that weren't
        modified

        This function was thought to update existing objects, it shouldn't
        be used when creating!
        """
        return set_children_objects(self, new_hostnames,
                                    parent_field='hostnames',
                                    child_field='name')


def set_children_objects(instance, value, parent_field, child_field='id',
                         workspaced=True):
    """
    Override some kind of children of instance. This is useful in one
    to many relationships. It takes care of deleting not used children,
    adding new objects, and keeping the not modified ones the same.

    :param instance: instance of the parent object
    :param value: list of childs (values of the child_field)
    :param parent_field: the parent field's relationship to the children name
    :param child_field: the "lookup field" of the children model
    :param workspaced: indicates if the parent model has a workspace
    """
    # Get the class of the children. Inspired in
    # https://stackoverflow.com/questions/6843144/how-to-find-sqlalchemy-remote-side-objects-class-or-class-name-without-db-queri
    children_model = getattr(
        type(instance), parent_field).property.mapper.class_

    value = set(value)
    current_value = getattr(instance, parent_field)
    current_value_fields = set(map(operator.attrgetter(child_field),
                                   current_value))

    for existing_child in current_value_fields:
        if existing_child not in value:
            # It was removed
            removed_instance = next(
                inst for inst in current_value
                if getattr(inst, child_field) == existing_child)
            db.session.delete(removed_instance)

    for new_child in value:
        if new_child in current_value_fields:
            # it already exists
            continue
        kwargs = {child_field: new_child}
        if workspaced:
            kwargs['workspace'] = instance.workspace
        current_value.append(children_model(**kwargs))


class Hostname(Metadata):
    __tablename__ = 'hostname'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    host_id = Column(Integer, ForeignKey('host.id'), index=True, nullable=False)
    host = relationship('Host', backref=backref("hostnames", cascade="all, delete-orphan"))
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
    name = BlankColumn(Text)
    description = BlankColumn(Text)
    port = Column(Integer, nullable=False)
    owned = Column(Boolean, nullable=False, default=False)

    protocol = NonBlankColumn(Text)
    status = Column(Enum(*STATUSES, name='service_statuses'), nullable=False)
    version = BlankColumn(Text)

    banner = BlankColumn(Text)

    host_id = Column(Integer, ForeignKey('host.id'), index=True, nullable=False)
    host = relationship(
        'Host',
        foreign_keys=[host_id],
    )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('services', cascade="all, delete-orphan"),
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

    @property
    def summary(self):
        if self.version and self.version.lower() != "unknown":
            version = " (" + self.version + ")"
        else:
            version = ""
        return "(%s/%s) %s%s" % (self.port, self.protocol, self.name,
                                 version or "")


class CustomFieldsSchema(db.Model):
    __tablename__ = 'custom_fields_schema'

    id = Column(Integer, primary_key=True)
    field_name = Column(Text, unique=True)
    field_type = Column(Text)
    field_display_name = Column(Text)
    field_order = Column(Integer)
    table_name = Column(Text)


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

    data = BlankColumn(Text)
    description = BlankColumn(Text)
    ease_of_resolution = Column(Enum(*EASE_OF_RESOLUTIONS, name='vulnerability_ease_of_resolution'), nullable=True)
    name = NonBlankColumn(Text, nullable=False)
    resolution = BlankColumn(Text)
    severity = Column(Enum(*SEVERITIES, name='vulnerability_severity'), nullable=False)
    risk = Column(Float(3, 1), nullable=True)

    impact_accountability = Column(Boolean, default=False, nullable=False)
    impact_availability = Column(Boolean, default=False, nullable=False)
    impact_confidentiality = Column(Boolean, default=False, nullable=False)
    impact_integrity = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        CheckConstraint('1.0 <= risk AND risk <= 10.0',
                        name='check_vulnerability_risk'),
    )

    custom_fields = Column(JSONType)

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

        if getattr(parent, 'getset_factory', False):
            getter, setter = parent.getset_factory(
                parent.collection_class, parent)
        else:
            getter, setter = parent._default_getset(parent.collection_class)

        super(CustomAssociationSet, self).__init__(
            lazy_collection, creator, getter, setter, parent)

    def _create(self, value):
        if getattr(self.lazy_collection, 'ref', False):
            # for sqlalchemy previous to 1.3.0b1
            parent_instance = self.lazy_collection.ref()
        else:
            parent_instance = self.lazy_collection.parent
        session = db.session
        conflict_objs = session.new
        try:
            yield self.creator(value, parent_instance)
        except IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                raise
            # unique constraint failed at database
            # other process/thread won us on the commit
            # we need to fetch already created objs.
            session.rollback()
            for conflict_obj in conflict_objs:
                if not hasattr(conflict_obj, 'name'):
                    # The session can hold elements without a name (altough it shouldn't)
                    continue
                if conflict_obj.name == value:
                    continue
                persisted_conclict_obj = session.query(conflict_obj.__class__).filter_by(name=conflict_obj.name).first()
                if persisted_conclict_obj:
                    self.col.add(persisted_conclict_obj)
            yield self.creator(value, parent_instance)

    def add(self, value):
        if value not in self:
            for new_value in self._create(value):
                self.col.add(new_value)

def _build_associationproxy_creator(model_class_name):
    def creator(name, vulnerability):
        """Get or create a reference/policyviolation with the
        corresponding name. This must be workspace aware"""

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
        corresponding name. This must be workspace aware"""

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
        'reference_template_instances',
        'name',
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
        'policy_violation_template_instances',
        'name',
        proxy_factory=CustomAssociationSet,
        creator=_build_associationproxy_creator_non_workspaced('PolicyViolationTemplate')
    )
    custom_fields = Column(JSONType)


class CommandObject(db.Model):
    __tablename__ = 'command_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)

    command = relationship('Command', backref='command_objects')
    command_id = Column(Integer, ForeignKey('command.id'), index=True)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref = backref('command_objects', cascade="all, delete-orphan")
    )

    create_date = Column(DateTime, default=datetime.utcnow)

    # the following properties are used to know if the command created the specified objects_type
    # remeber that this table has a row instances per relationship.
    # this created integer can be used to obtain the total object_type objects created.
    created = _make_command_created_related_object()

    # We are currently using the column property created. however to avoid losing information
    # we also store the a boolean to know if at the moment of created the object related to the
    # Command was created.
    created_persistent = Column(Boolean, nullable=False)

    __table_args__ = (
        UniqueConstraint('object_id', 'object_type', 'command_id', 'workspace_id',
                         name='uix_command_object_objid_objtype_command_id_ws'),
    )

    @property
    def parent(self):
        return self.command

    @classmethod
    def create(cls, obj, command, add_to_session=True, **kwargs):
        co = cls(obj, workspace=command.workspace, command=command,
                 created_persistent=True, **kwargs)
        if add_to_session:
            db.session.add(co)
        return co

    def __init__(self, object_=None, **kwargs):

        if object_ is not None:
            assert 'object_type' not in kwargs
            assert 'object_id' not in kwargs
            object_type = get_object_type_for(object_)

            # db.session.flush()
            assert object_.id is not None, "object must have an ID. Try " \
                "flushing the session"
            kwargs['object_id'] = object_.id
            kwargs['object_type'] = object_type
        return super(CommandObject, self).__init__(**kwargs)


def _make_created_objects_sum(object_type_filter):
    where_conditions = ["command_object.object_type= '%s'" % object_type_filter]
    where_conditions.append("command_object.command_id = command.id")
    where_conditions.append("command_object.workspace_id = command.workspace_id")
    return column_property(
        select([func.sum(CommandObject.created)]).
        select_from(table('command_object')).
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
    command = NonBlankColumn(Text)
    tool = NonBlankColumn(Text)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=True)
    ip = BlankColumn(String(250))  # where the command was executed
    hostname = BlankColumn(String(250))  # where the command was executed
    params = BlankColumn(Text)
    user = BlankColumn(String(250))  # os username where the command was executed
    import_source = Column(Enum(*IMPORT_SOURCE, name='import_source_enum'))

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('commands', cascade="all, delete-orphan")
    )

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
    issuetracker = BlankColumn(Text)

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
        cascade="all, delete-orphan"
    )

    tags = relationship(
        "Tag",
        secondary="tag_object",
        primaryjoin="and_(TagObject.object_id==VulnerabilityGeneric.id, "
                    "TagObject.object_type=='vulnerability')",
        collection_class=set,
    )

    creator_command_id = column_property(
        select([CommandObject.command_id])
        .where(CommandObject.object_type == 'vulnerability')
        .where(text('command_object.object_id = vulnerability.id'))
        .where(CommandObject.workspace_id == workspace_id)
        .order_by(asc(CommandObject.create_date))
        .limit(1),
        deferred=True)

    creator_command_tool = column_property(
        select([Command.tool])
        .select_from(join(Command, CommandObject,
                          Command.id == CommandObject.command_id))
        .where(CommandObject.object_type == 'vulnerability')
        .where(text('command_object.object_id = vulnerability.id'))
        .where(CommandObject.workspace_id == workspace_id)
        .order_by(asc(CommandObject.create_date))
        .limit(1),
        deferred=True
    )

    _host_ip_query = (
        select([Host.ip])
        .where(text('vulnerability.host_id = host.id'))
    )
    _service_ip_query = (
        select([text('host_inner.ip')])
        .select_from(text('host as host_inner, service'))
        .where(text('vulnerability.service_id = service.id and '
                    'host_inner.id = service.host_id'))
    )
    target_host_ip = column_property(
        case([
            (text('vulnerability.host_id IS NOT null'),
                _host_ip_query.as_scalar()),
            (text('vulnerability.service_id IS NOT null'),
                _service_ip_query.as_scalar())
        ]),
        deferred=True
    )

    _host_os_query = (
        select([Host.os])
        .where(text('vulnerability.host_id = host.id'))
    )
    _service_os_query = (
        select([text('host_inner.os')])
        .select_from(text('host as host_inner, service'))
        .where(text('vulnerability.service_id = service.id and '
                    'host_inner.id = service.host_id'))
    )
    target_host_os = column_property(
        case([
            (text('vulnerability.host_id IS NOT null'),
                _host_os_query.as_scalar()),
            (text('vulnerability.service_id IS NOT null'),
                _service_os_query.as_scalar())
        ]),
        deferred=True
    )

    __mapper_args__ = {
        'polymorphic_on': type
    }

    @property
    def attachments(self):
        return db.session.query(File).filter_by(
            object_id=self.id,
            object_type='vulnerability'
        )

    @hybrid_property
    def target(self):
        return self.target_host_ip


class Vulnerability(VulnerabilityGeneric):
    __tablename__ = None
    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship(
        'Host',
        backref=backref("vulnerabilities", cascade="all, delete-orphan"),
        foreign_keys=[host_id],
    )

    @declared_attr
    def service_id(cls):
        return VulnerabilityGeneric.__table__.c.get('service_id', Column(Integer, db.ForeignKey('service.id'),
                                                                         index=True))

    @declared_attr
    def service(cls):
        return relationship('Service', backref=backref("vulnerabilities", cascade="all, delete-orphan"))

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
    method = BlankColumn(Text)
    parameters = BlankColumn(Text)
    parameter_name = BlankColumn(Text)
    path = BlankColumn(Text)
    query_string = BlankColumn(Text)
    request = BlankColumn(Text)
    response = BlankColumn(Text)
    website = BlankColumn(Text)
    status_code = Column(Integer, nullable=True)

    @declared_attr
    def service_id(cls):
        return VulnerabilityGeneric.__table__.c.get(
            'service_id', Column(Integer, db.ForeignKey('service.id'),
                                 nullable=False))

    @declared_attr
    def service(cls):
        return relationship('Service', backref=backref("vulnerabilities_web", cascade="all, delete-orphan"))

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
    code = BlankColumn(Text)
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
    name = NonBlankColumn(Text)

    __table_args__ = (
        UniqueConstraint('name', name='uix_reference_template_name'),
    )

    def __init__(self, name=None, **kwargs):
        super(ReferenceTemplate, self).__init__(name=name,
                                        **kwargs)


class Reference(Metadata):
    __tablename__ = 'reference'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    workspace_id = Column(
        Integer,
        ForeignKey('workspace.id'),
        index=True,
        nullable=False
    )
    workspace = relationship(
        'Workspace',
        backref=backref("references",
                        cascade="all, delete-orphan"),
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

    reference = relationship("Reference",
                             backref=backref(
                                 "reference_associations",
                                 cascade="all, delete-orphan"),
                             foreign_keys=[reference_id])
    vulnerability = relationship("Vulnerability",
                                 backref=backref("reference_vulnerability_associations",
                                                 cascade="all, delete-orphan"),
                                 foreign_keys=[vulnerability_id])


class PolicyViolationVulnerabilityAssociation(db.Model):

    __tablename__ = 'policy_violation_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability.id'), primary_key=True)
    policy_violation_id = Column(Integer, ForeignKey('policy_violation.id'), primary_key=True)

    policy_violation = relationship("PolicyViolation", backref="policy_violation_associations", foreign_keys=[policy_violation_id])
    vulnerability = relationship("Vulnerability", backref=backref("policy_violationvulnerability_associations", cascade="all, delete-orphan"),
                                 foreign_keys=[vulnerability_id])


class ReferenceTemplateVulnerabilityAssociation(db.Model):

    __tablename__ = 'reference_template_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability_template.id'), primary_key=True)
    reference_id = Column(Integer, ForeignKey('reference_template.id'), primary_key=True)

    reference = relationship(
        "ReferenceTemplate",
        foreign_keys=[reference_id],
        backref=backref('reference_template_associations', cascade="all, delete-orphan")
    )
    vulnerability = relationship(
        "VulnerabilityTemplate",
        backref=backref('reference_template_vulnerability_associations',
                        cascade="all, delete-orphan"),
        foreign_keys=[vulnerability_id]
    )


class PolicyViolationTemplateVulnerabilityAssociation(db.Model):

    __tablename__ = 'policy_violation_template_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability_template.id'), primary_key=True)
    policy_violation_id = Column(Integer, ForeignKey('policy_violation_template.id'), primary_key=True)

    policy_violation = relationship("PolicyViolationTemplate", backref="policy_violation_template_associations", foreign_keys=[policy_violation_id])
    vulnerability = relationship("VulnerabilityTemplate", backref=backref("policy_violation_template_vulnerability_associations", cascade="all, delete-orphan"),
                                 foreign_keys=[vulnerability_id])


class PolicyViolationTemplate(Metadata):
    __tablename__ = 'policy_violation_template'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

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
    name = NonBlankColumn(Text)

    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True,
                        nullable=False
                        )
    workspace = relationship(
                            'Workspace',
                            backref=backref("policy_violations",
                                            cascade="all, delete-orphan"),
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
    username = BlankColumn(Text)
    password = BlankColumn(Text)
    description = BlankColumn(Text)
    name = BlankColumn(Text)

    host_id = Column(Integer, ForeignKey(Host.id), index=True, nullable=True)
    host = relationship(
        'Host',
        backref=backref("credentials", cascade="all, delete-orphan"),
        foreign_keys=[host_id])

    service_id = Column(Integer, ForeignKey(Service.id), index=True, nullable=True)
    service = relationship(
        'Service',
        backref=backref('credentials', cascade="all, delete-orphan"),
        foreign_keys=[service_id],
        )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('credentials', cascade="all, delete-orphan"),
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


def _make_vuln_count_property(type_=None, confirmed=None,
                              use_column_property=True, extra_query=None, get_hosts_vulns=False):
    from_clause = table('vulnerability')

    if get_hosts_vulns:
        from_clause = from_clause.join(
            Service, Vulnerability.service_id == Service.id,
            isouter=True
        )

    query = (select([func.count(text('distinct(vulnerability.id)'))]).
             select_from(from_clause)
             )
    if get_hosts_vulns:
        query = query.where(text('(vulnerability.host_id = host.id OR host.id = service.host_id)'))
    else:
        query = query.where(text('vulnerability.workspace_id = workspace.id'))

    if type_:
        # Don't do queries using this style!
        # This can cause SQL injection vulnerabilities
        # In this case type_ is supplied from a whitelist so this is safe
        query = query.where(text("vulnerability.type = '%s'" % type_))
    if confirmed:
        if db.session.bind.dialect.name == 'sqlite':
            # SQLite has no "true" expression, we have to use the integer 1
            # instead
            query = query.where(text("vulnerability.confirmed = 1"))
        elif db.session.bind.dialect.name == 'postgresql':
            # I suppose that we're using PostgreSQL, that can't compare
            # booleans with integers
            query = query.where(text("vulnerability.confirmed = true"))
    elif confirmed == False:
        if db.session.bind.dialect.name == 'sqlite':
            # SQLite has no "true" expression, we have to use the integer 1
            # instead
            query = query.where(text("vulnerability.confirmed = 0"))
        elif db.session.bind.dialect.name == 'postgresql':
            # I suppose that we're using PostgreSQL, that can't compare
            # booleans with integers
            query = query.where(text("vulnerability.confirmed = false"))

    if extra_query:
        query = query.where(text(extra_query))
    if use_column_property:
        return column_property(query, deferred=True)
    else:
        return query


class Workspace(Metadata):
    __tablename__ = 'workspace'
    id = Column(Integer, primary_key=True)
    customer = BlankColumn(String(250))  # TBI
    description = BlankColumn(Text)
    active = Column(Boolean(), nullable=False, default=True)  # TBI
    readonly = Column(Boolean(), nullable=False, default=False)  # TBI
    end_date = Column(DateTime(), nullable=True)
    name = NonBlankColumn(String(250), unique=True, nullable=False)
    public = Column(Boolean(), nullable=False, default=False)  # TBI
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

    workspace_permission_instances = relationship(
        "WorkspacePermission",
        cascade="all, delete-orphan")

    @classmethod
    def query_with_count(cls, confirmed, active=True, readonly=None, workspace_name=None):
        """
        Add count fields to the query.

        If confirmed is True/False, it will only show the count for confirmed / not confirmed
        vulnerabilities. Otherwise, it will show the count of all of them
        """
        query = """
                SELECT
                (SELECT COUNT(credential.id) AS count_1
                    FROM credential
                    WHERE credential.workspace_id = workspace.id
                ) AS credentials_count,
                (SELECT COUNT(host.id) AS count_2
                    FROM host
                    WHERE host.workspace_id = workspace.id
                ) AS host_count,
                p_4.count_3 as open_services,
                p_4.count_4 as total_service_count,
                p_5.count_5 as vulnerability_web_count,
                p_5.count_6 as vulnerability_code_count,
                p_5.count_7 as vulnerability_standard_count,
                p_5.count_8 as vulnerability_total_count,
                workspace.create_date AS workspace_create_date,
                workspace.update_date AS workspace_update_date,
                workspace.id AS workspace_id,
                workspace.customer AS workspace_customer,
                workspace.description AS workspace_description,
                workspace.active AS workspace_active,
                workspace.readonly AS workspace_readonly,
                workspace.end_date AS workspace_end_date,
                workspace.name AS workspace_name,
                workspace.public AS workspace_public,
                workspace.start_date AS workspace_start_date,
                workspace.update_user_id AS workspace_update_user_id,
                workspace.creator_id AS workspace_creator_id,
                (SELECT {concat_func}(scope.name, ',') FROM scope where scope.workspace_id=workspace.id) as scope_raw
            FROM workspace
            LEFT JOIN (SELECT w.id as wid, COUNT(case when service.id IS NOT NULL and service.status = 'open' then 1 else null end) as count_3, COUNT(case when service.id IS NOT NULL then 1 else null end) AS count_4
                    FROM service
                    RIGHT JOIN workspace w ON service.workspace_id = w.id
                    GROUP BY w.id
                ) AS p_4 ON p_4.wid = workspace.id
            LEFT JOIN (SELECT w.id as w_id, COUNT(case when vulnerability.type = 'vulnerability_web' then 1 else null end) as count_5, COUNT(case when vulnerability.type = 'vulnerability_code' then 1 else null end) AS count_6, COUNT(case when vulnerability.type = 'vulnerability' then 1 else null end) as count_7, COUNT(case when vulnerability.id IS NOT NULL then 1 else null end) AS count_8
                    FROM vulnerability
                    RIGHT JOIN workspace w ON vulnerability.workspace_id = w.id
                    WHERE 1=1 {0}
                    GROUP BY w.id
                ) AS p_5 ON p_5.w_id = workspace.id
        """
        concat_func = 'string_agg'
        if db.engine.dialect.name == 'sqlite':
            concat_func = 'group_concat'
        filters = []
        params = {}

        confirmed_vuln_filter = ''
        if confirmed is not None:
            if confirmed:
                confirmed_vuln_filter = " AND vulnerability.confirmed "
            else:
                confirmed_vuln_filter = " AND NOT vulnerability.confirmed "
        query = query.format(confirmed_vuln_filter, concat_func=concat_func)

        if active is not None:
            filters.append(" workspace.active = :active ")
            params['active'] = active
        if readonly is not None:
            filters.append(" workspace.readonly = :readonly ")
            params['readonly'] = readonly
        if workspace_name:
            filters.append(" workspace.name = :workspace_name ")
            params['workspace_name'] = workspace_name
        if filters:
            query += ' WHERE ' + ' AND '.join(filters)
        #query += " GROUP BY workspace.id "
        query += " ORDER BY workspace.name ASC"
        return db.session.execute(text(query), params)

    def set_scope(self, new_scope):
        return set_children_objects(self, new_scope,
                                    parent_field='scope',
                                    child_field='name',
                                    workspaced=False)

    def activate(self):
        # if Checks active count
        if not self.active:
            self.active = True
            return True
        return False
        # else:
        # raise Cannot exceed or return false

    def deactivate(self):
        if self.active is not False:
            self.active = False
            return True
        return False

    def change_readonly(self):
        self.readonly = not self.readonly


class Scope(Metadata):
    __tablename__ = 'scope'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    workspace_id = Column(
                        Integer,
                        ForeignKey('workspace.id'),
                        index=True,
                        nullable=False
                        )

    workspace = relationship(
        'Workspace',
         backref=backref('scope', cascade="all, delete-orphan"),
         foreign_keys=[workspace_id],
         )

    __table_args__ = (
        UniqueConstraint('name', 'workspace_id',
                         name='uix_scope_name_workspace'),
    )

    @property
    def parent(self):
        return


class WorkspacePermission(db.Model):
    __tablename__ = "workspace_permission_association"
    id = Column(Integer, primary_key=True)
    workspace_id = Column(
        Integer, ForeignKey('workspace.id'), nullable=False)
    workspace = relationship('Workspace')

    user_id = Column(Integer, ForeignKey('faraday_user.id'), nullable=False)
    user = relationship('User',
                        foreign_keys=[user_id])

    @property
    def parent(self):
        return


def get(workspace_name):
    return db.session.query(Workspace).filter_by(name=workspace_name).first()


class User(db.Model, UserMixin):

    __tablename__ = 'faraday_user'
    ROLES = ['admin', 'pentester', 'client']
    OTP_STATES = ["disabled", "requested", "confirmed"]

    id = Column(Integer, primary_key=True)
    username = NonBlankColumn(String(255), unique=True)
    password = Column(String(255), nullable=True)
    email = Column(String(255), unique=True, nullable=True)  # TBI
    name = BlankColumn(String(255))  # TBI
    is_ldap = Column(Boolean(), nullable=False, default=False)
    last_login_at = Column(DateTime())  # flask-security
    current_login_at = Column(DateTime())  # flask-security
    last_login_ip = BlankColumn(String(100))  # flask-security
    current_login_ip = BlankColumn(String(100))  # flask-security
    login_count = Column(Integer)  # flask-security
    active = Column(Boolean(), default=True, nullable=False)  # TBI flask-security
    confirmed_at = Column(DateTime())
    role = Column(Enum(*ROLES, name='user_roles'),
                  nullable=False, default='client')
    _otp_secret = Column(
            String(16),
            name="otp_secret", nullable=True)
    state_otp = Column(Enum(*OTP_STATES, name='user_otp_states'), nullable=False, default="disabled")

    # TODO: add  many to many relationship to add permission to workspace

    workspace_permission_instances = relationship(
        "WorkspacePermission",
        cascade="all, delete-orphan")

    def __init__(self, *args, **kwargs):
        # added for compatibility with flask security
        try:
            kwargs.pop('roles')
        except KeyError:
            pass
        super(User, self).__init__(*args, **kwargs)

    def __repr__(self):
        return '<%sUser: %s>' % ('LDAP ' if self.is_ldap else '',
                                 self.username)

    def get_security_payload(self):
        return {
            "username": self.username,
            "name": self.email
        }


class File(Metadata):
    __tablename__ = 'file'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = BlankColumn(Text)  # TODO migration: check why blank is allowed
    filename = NonBlankColumn(Text)
    description = BlankColumn(Text)
    content = Column(UploadedFileField(upload_type=FaradayUploadedFile),
                     nullable=False)  # plain attached file
    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)


class UserAvatar(Metadata):
    __tablename_ = 'user_avatar'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = BlankColumn(Text, unique=True)
    # photo field will automatically generate thumbnail
    # if the file is a valid image
    photo = Column(UploadedFileField(upload_type=FaradayUploadedFile))
    user_id = Column('user_id', Integer(), ForeignKey('faraday_user.id'))
    user = relationship('User', foreign_keys=[user_id])


class MethodologyTemplate(Metadata):
    # TODO: reset template_id in methodologies when deleting meth template
    __tablename__ = 'methodology_template'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)


class Methodology(Metadata):
    # TODO: add unique constraint -> name, workspace
    __tablename__ = 'methodology'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    template = relationship(
        'MethodologyTemplate',
        backref=backref('methodologies')
    )
    template_id = Column(
                    Integer,
                    ForeignKey('methodology_template.id',
                               ondelete="SET NULL"),
                    index=True,
                    nullable=True,
                    )

    workspace = relationship(
        'Workspace',
        backref=backref('methodologies', cascade="all, delete-orphan"),
    )
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)

    @property
    def parent(self):
        return


class TaskABC(Metadata):
    __abstract__ = True

    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)
    description = BlankColumn(Text)


class TaskTemplate(TaskABC):
    __tablename__ = 'task_template'
    id = Column(Integer, primary_key=True)

    __mapper_args__ = {
        'concrete': True
    }

    template = relationship(
        'MethodologyTemplate',
        backref=backref('tasks', cascade="all, delete-orphan"))
    template_id = Column(
                    Integer,
                    ForeignKey('methodology_template.id'),
                    index=True,
                    nullable=False,
                    )

    # __table_args__ = (
    #     UniqueConstraint(template_id, name='uix_task_template_name_desc_template_delete'),
    # )


class TaskAssignedTo(db.Model):
    __tablename__ = "task_assigned_to_association"
    id = Column(Integer, primary_key=True)
    task_id = Column(
        Integer, ForeignKey('task.id'), nullable=False)
    task = relationship('Task')

    user_id = Column(Integer, ForeignKey('faraday_user.id'), nullable=False)
    user = relationship(
        'User',
        foreign_keys=[user_id],
        backref=backref('assigned_tasks', cascade="all, delete-orphan"))


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

    assigned_to = relationship(
        "User",
        secondary="task_assigned_to_association")

    methodology_id = Column(
                    Integer,
                    ForeignKey('methodology.id'),
                    index=True,
                    nullable=False,
                    )
    methodology = relationship(
        'Methodology',
        backref=backref('tasks', cascade="all, delete-orphan")
    )

    template_id = Column(
                    Integer,
                    ForeignKey('task_template.id'),
                    index=True,
                    nullable=True,
                    )
    template = relationship('TaskTemplate', backref='tasks')

    workspace = relationship(
        'Workspace',
        backref=backref('tasks', cascade="all, delete-orphan")
    )
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
    product = NonBlankColumn(Text)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)

    type = BlankColumn(Text)
    notes = BlankColumn(Text)

    __table_args__ = (
        UniqueConstraint('product', 'start_date', 'end_date', name='uix_license_product_start_end_dates'),
    )


class Tag(Metadata):
    __tablename__ = 'tag'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text, unique=True)
    slug = NonBlankColumn(Text, unique=True)


class TagObject(db.Model):
    __tablename__ = 'tag_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)
    tag = relationship('Tag', backref='tagged_objects')
    tag_id = Column(Integer, ForeignKey('tag.id'), index=True)


class Comment(Metadata):
    __tablename__ = 'comment'
    id = Column(Integer, primary_key=True)

    text = BlankColumn(Text)

    reply_to_id = Column(Integer, ForeignKey('comment.id'))
    reply_to = relationship(
        'Comment',
        remote_side=[id],
        foreign_keys=[reply_to_id]
    )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True,
                          nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('comments', cascade="all, delete-orphan"),
    )

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)

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
    name = NonBlankColumn(Text, index=True)
    status = Column(Enum(*STATUSES, name='executive_report_statuses'), nullable=False, default='processing')
    template_name = NonBlankColumn(Text)

    conclusions = BlankColumn(Text)
    enterprise = BlankColumn(Text)
    objectives = BlankColumn(Text)
    recommendations = BlankColumn(Text)
    scope = BlankColumn(Text)
    summary = BlankColumn(Text)
    title = BlankColumn(Text)
    confirmed = Column(Boolean, nullable=False, default=False)
    vuln_count = Column(Integer, default=0)  # saves the amount of vulns when the report was generated.
    markdown = Column(Boolean, default=False, nullable=False)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('reports', cascade="all, delete-orphan"),
        foreign_keys=[workspace_id]
    )
    tags = relationship(
        "Tag",
        secondary="tag_object",
        primaryjoin="and_(TagObject.object_id==ExecutiveReport.id, "
                    "TagObject.object_type=='executive_report')",
        collection_class=set,
    )
    @property
    def parent(self):
        return

    @property
    def attachments(self):
        return db.session.query(File).filter_by(
            object_id=self.id,
            object_type='executive_report'
        )


class Notification(db.Model):

    __tablename__ = 'notification'
    id = Column(Integer, primary_key=True)

    user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=False)
    user_notified = relationship(
        'User',
        backref=backref('notification', cascade="all, delete-orphan"),
        #primaryjoin="User.id == Notification.user_notified_id"
    )

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)
    notification_text = Column(Text, nullable=False)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('notification', cascade="all, delete-orphan"),
        #primaryjoin="Notification.id == Notification.workspace_id"
    )

    mark_read = Column(Boolean, default=False, index=True)
    create_date = Column(DateTime, default=datetime.utcnow)

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
    "(md5(name), md5(description), type, COALESCE(host_id, -1), COALESCE(service_id, -1), "
    "COALESCE(md5(method), ''), COALESCE(md5(parameter_name), ''), COALESCE(md5(path), ''), "
    "COALESCE(md5(website), ''), workspace_id, COALESCE(source_code_id, -1));"
)

vulnerability_uniqueness_sqlite = DDL(
    "CREATE UNIQUE INDEX uix_vulnerability ON %(fullname)s "
    "(name, description, type, COALESCE(host_id, -1), COALESCE(service_id, -1), "
    "COALESCE(method, ''), COALESCE(parameter_name, ''), COALESCE(path, ''), "
    "COALESCE(website, ''), workspace_id, COALESCE(source_code_id, -1));"
)


event.listen(
    VulnerabilityGeneric.__table__,
    'after_create',
    vulnerability_uniqueness.execute_if(dialect='postgresql')
)

event.listen(
    VulnerabilityGeneric.__table__,
    'after_create',
    vulnerability_uniqueness_sqlite.execute_if(dialect='sqlite')
)

# We have to import this after all models are defined
import faraday.server.events
