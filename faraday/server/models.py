"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging
import operator
import string
import time
from datetime import datetime, timedelta, date
from functools import partial
from random import SystemRandom
from typing import Callable

# Related third party imports
import dateutil
import cvss
import jwt
from croniter import croniter
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
    Table,
    Date,
    event,
    literal,
    func,
    Index,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import select, text, table
from sqlalchemy.sql.expression import asc, case, join
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.ext.associationproxy import association_proxy, _AssociationSet
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import (
    backref,
    column_property,
    query_expression,
    with_expression,
    relationship,
    undefer,
    joinedload,
)
from sqlalchemy.schema import DDL
from flask import (
    current_app as app,
)
from flask_sqlalchemy import (
    SQLAlchemy as OriginalSQLAlchemy,
    _EngineConnector,
)
from flask_security import UserMixin, RoleMixin
from flask_security.utils import hash_data
from depot.fields.sqlalchemy import UploadedFileField

# Local application imports
from faraday.server.config import faraday_server
from faraday.server.fields import JSONType, FaradayUploadedFile
from faraday.server.utils.cvss import (
    get_propper_value,
    get_severity,
    get_base_score,
    get_temporal_score,
    get_environmental_score,
    get_exploitability_score,
    get_impact_score
)
from faraday.server.utils.database import (
    BooleanToIntColumn,
    get_object_type_for,
    is_unique_constraint_violation,
)

logger = logging.getLogger(__name__)

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
    'task',
    'report_logo',
    'report_template',
]

REFERENCE_TYPES = [
    'exploit',
    'patch',
    'other',
]

COMMENT_TYPES = [
    'system',
    'user'
]

NOTIFICATION_METHODS = [
    'mail',
    'webhook',
    'websocket'
]

LDAP_TYPE = 'ldap'
LOCAL_TYPE = 'local'
SAML_TYPE = 'saml'


class SQLAlchemy(OriginalSQLAlchemy):
    """Override to fix issues when doing a rollback with sqlite driver
    See https://docs.sqlalchemy.org/en/14/dialects/sqlite.html#serializable-isolation-savepoints-transactional-ddl
    and https://bitbucket.org/zzzeek/sqlalchemy/issues/3561/sqlite-nested-transactions-fail-with
    for further information"""

    def make_connector(self, app=None, bind=None):
        """Creates the connector for a given state and bind."""
        return CustomEngineConnector(self, self.get_app(app), bind)


class CustomEngineConnector(_EngineConnector):
    """Used by overridden SQLAlchemy class to fix rollback issues.

    Also set case sensitive likes (in SQLite there are case
    insensitive by default)"""

    def get_engine(self):
        # Use an existent engine and don't register events if possible
        uri = self.get_uri()
        echo = self._app.config['SQLALCHEMY_ECHO']
        if (uri, echo) == self._connected_for:
            return self._engine

        # Call original method and register events
        rv = super().get_engine()
        if uri.startswith('sqlite://'):
            with self._lock:
                @event.listens_for(rv, "connect")
                def do_connect(dbapi_connection, connection_record):  # pylint:disable=unused-variable
                    # disable pysqlite's emitting of the BEGIN statement
                    # entirely.  also stops it from emitting COMMIT before any
                    # DDL.
                    dbapi_connection.isolation_level = None
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA case_sensitive_like=true")
                    cursor.close()

                @event.listens_for(rv, "begin")
                def do_begin(conn):  # pylint:disable=unused-variable
                    # emit our own BEGIN
                    conn.execute("BEGIN")
        return rv


db = SQLAlchemy()


def _last_run_agent_date():
    query = select([text('executor.last_run')])

    from_clause = table('executor') \
        .join(AgentExecution, text('executor.id = agent_execution.executor_id'))
    where_clause = text('executor.last_run is not null and agent_execution.workspace_id = workspace.id')
    query = query.select_from(from_clause).where(where_clause).order_by(AgentExecution.create_date.desc()).limit(1)
    return query


def _make_generic_count_property(parent_table, children_table, where=None, use_column_property=True):
    """Make a deferred by default column property that counts the
    amount of children of some parent object"""
    children_id_field = f'{children_table}.id'
    parent_id_field = f'{parent_table}.id'
    children_rel_field = f'{children_table}.{parent_table}_id'
    query = (select([func.count(text(children_id_field))]).
             select_from(table(children_table)).
             where(text(f'{children_rel_field} = {parent_id_field}')))
    if where is not None:
        query = query.where(where)
    if use_column_property:
        return column_property(query, deferred=True)
    return query


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


def _make_vuln_count_property(type_=None, confirmed=None, use_column_property=True,
                              extra_query=None, get_hosts_vulns=False):
    from_clause = table('vulnerability')
    if get_hosts_vulns:
        from_clause = from_clause.join(
            table("service"), text("vulnerability.service_id = service.id"),
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
        query = query.where(text(f"vulnerability.type = '{type_}'"))
    if confirmed:
        if db.session.bind.dialect.name == 'sqlite':
            # SQLite has no "true" expression, we have to use the integer 1
            # instead
            query = query.where(text("vulnerability.confirmed = 1"))
        elif db.session.bind.dialect.name == 'postgresql':
            # I suppose that we're using PostgreSQL, that can't compare
            # booleans with integers
            query = query.where(text("vulnerability.confirmed = true"))
    elif confirmed is False:
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


def count_vulnerability_severities(query: str,
                                   model: db.Model,
                                   confirmed: bool = None,
                                   all_severities: bool = False,
                                   critical: bool = False,
                                   informational: bool = False,
                                   high: bool = False,
                                   medium: bool = False,
                                   low: bool = False,
                                   unclassified: bool = False,
                                   host_vulns: bool = False,
                                   only_opened: bool = False):
    """
    We assume that vulnerability_SEVERITYNAME_count attr exists in the model passed by param
    :param query: Alchemy query to append options
    :param model: model class
    :param only_opened: Only risk-accepted, open and re-opened vulns with those status will be counted
    :param confirmed: if vuln is confirmed or not
    :param all_severities: All severities will be counted
    :param critical: Critical severities will be counted if True
    :param informational: Informational severities will be counted if True
    :param high: High severities will be counted if True
    :param medium: Medium severities will be counted if True
    :param low: Low severities will be counted if True
    :param unclassified: Unclassified severities will be counted  if True
    :param host_vulns: Hosts will be counted  if True
    :return: Query with options added
    """

    severities = {
        'informational': all_severities or informational,
        'critical': all_severities or critical,
        'high': all_severities or high,
        'medium': all_severities or medium,
        'low': all_severities or low,
        'unclassified': all_severities or unclassified
    }

    extra_query = None
    if only_opened:
        extra_query = "status != 'closed'"

    for severity_name, filter_severity in severities.items():
        if filter_severity:
            _extra_query = f"{extra_query} AND severity = '{severity_name}'" \
                if extra_query else f"severity = '{severity_name}'"
            query = query.options(
                with_expression(
                    getattr(model, f'vulnerability_{severity_name}_count'),
                    _make_vuln_count_property(None,
                                              extra_query=_extra_query,
                                              use_column_property=False,
                                              get_hosts_vulns=host_vulns,
                                              confirmed=confirmed)
                )
            )
    return query


def _make_vuln_generic_count_by_severity(severity):
    assert severity in ['critical', 'high', 'medium', 'low', 'informational', 'unclassified']

    vuln_count = (
        select([func.count(text('vulnerability.id'))]).
        select_from(text('vulnerability')).
        where(text(f'vulnerability.host_id = host.id and vulnerability.severity = \'{severity}\'')).
        as_scalar()
    )

    vuln_web_count = (
        select([func.count(text('vulnerability.id'))]).
        select_from(text('vulnerability, service')).
        where(text('(vulnerability.service_id = service.id and '
                   f'service.host_id = host.id) and vulnerability.severity = \'{severity}\'')).
        as_scalar()
    )

    vulnerability_generic_count = column_property(
        vuln_count + vuln_web_count,
        deferred=True
    )

    return vulnerability_generic_count


class DatabaseMetadata(db.Model):
    __tablename__ = 'db_metadata'
    id = Column(Integer, primary_key=True)
    option = Column(String(250), nullable=False)
    value = Column(String(250), nullable=False)


class Metadata(db.Model):
    __abstract__ = True

    @declared_attr
    def creator_id(self):
        return Column(
            Integer,
            ForeignKey('faraday_user.id', ondelete="SET NULL"),
            nullable=True)

    @declared_attr
    def creator(self):
        return relationship('User', foreign_keys=[self.creator_id])

    @declared_attr
    def update_user_id(self):
        return Column(
            Integer,
            ForeignKey('faraday_user.id', ondelete="SET NULL"),
            nullable=True)

    @declared_attr
    def update_user(self):
        return relationship('User', foreign_keys=[self.update_user_id])

    create_date = Column(DateTime, default=datetime.utcnow)
    update_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SourceCode(Metadata):
    __tablename__ = 'source_code'
    id = Column(Integer, primary_key=True)
    filename = NonBlankColumn(Text)
    function = BlankColumn(Text)
    module = BlankColumn(Text)

    # 1 workspace <--> N source_codes
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', backref='source_codes')

    __table_args__ = (
        UniqueConstraint(filename, workspace_id, name='uix_source_code_filename_workspace'),
    )

    @property
    def parent(self):
        return


def set_children_objects(instance, value, parent_field, child_field='id', workspaced=True):
    """
    Override some kind of children of instance. This is useful in one
    to many relationships. It takes care of deleting not used children,
    adding new objects, and keeping the not modified ones the same.
    :param instance: instance of the parent object
    :param value: list of children (values of the child_field)
    :param parent_field: the parent field's relationship to the children name
    :param child_field: the "lookup field" of the children model
    :param workspaced: indicates if the parent model has a workspace
    """
    # Get the class of the children. Inspired in
    # https://stackoverflow.com/questions/6843144/how-to-find-sqlalchemy-remote-side-objects-class-or-class-name-without-db-queri
    children_model = getattr(type(instance), parent_field).property.mapper.class_

    value = set(value)
    current_value = getattr(instance, parent_field)
    current_value_fields = set(map(operator.attrgetter(child_field), current_value))

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

    host_id = Column(Integer, ForeignKey('host.id', ondelete='CASCADE'), index=True, nullable=False)
    host = relationship('Host', backref=backref("hostnames", cascade="all, delete-orphan"))

    # 1 workspace <--> N hostnames
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('hostnames', cascade="all, delete-orphan", passive_deletes=True),
    )

    __table_args__ = (
        UniqueConstraint(name, host_id, workspace_id, name='uix_hostname_host_workspace'),
    )

    def __str__(self):
        return self.name

    @property
    def parent(self):
        return self.host


class CustomFieldsSchema(db.Model):
    __tablename__ = 'custom_fields_schema'

    id = Column(Integer, primary_key=True)
    field_name = Column(Text, unique=True)
    field_type = Column(Text)
    field_metadata = Column(JSONType, nullable=True)
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

    SEVERITY_UNCLASSIFIED = 'unclassified'
    SEVERITY_INFORMATIONAL = 'informational'
    SEVERITY_LOW = 'low'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_HIGH = 'high'
    SEVERITY_CRITICAL = 'critical'

    SEVERITIES = [
        SEVERITY_UNCLASSIFIED,
        SEVERITY_INFORMATIONAL,
        SEVERITY_LOW,
        SEVERITY_MEDIUM,
        SEVERITY_HIGH,
        SEVERITY_CRITICAL,
    ]

    __abstract__ = True
    id = Column(Integer, primary_key=True)

    data = BlankColumn(Text)
    description = BlankColumn(Text)
    ease_of_resolution = Column(Enum(*EASE_OF_RESOLUTIONS, name='vulnerability_ease_of_resolution'), nullable=True)
    name = NonBlankColumn(Text, nullable=False)
    resolution = BlankColumn(Text)
    severity = Column(Enum(*SEVERITIES, name='vulnerability_severity'), nullable=False, index=True)
    risk = Column(Integer, nullable=True)

    impact_accountability = Column(Boolean, default=False, nullable=False)
    impact_availability = Column(Boolean, default=False, nullable=False)
    impact_confidentiality = Column(Boolean, default=False, nullable=False)
    impact_integrity = Column(Boolean, default=False, nullable=False)

    external_id = BlankColumn(Text)

    custom_fields = Column(JSONType)

    @property
    def parent(self):
        raise NotImplementedError('ABC property called')


class SeveritiesHistogram(db.Model):
    __tablename__ = "severities_histogram"
    __table_args__ = (
        UniqueConstraint('date', 'workspace_id', name='uix_severities_histogram_table_date_workspace_id'),
    )

    SEVERITIES_ALLOWED = [VulnerabilityABC.SEVERITY_MEDIUM,
                          VulnerabilityABC.SEVERITY_HIGH,
                          VulnerabilityABC.SEVERITY_CRITICAL]

    DEFAULT_DAYS_BEFORE = 20

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('severities_histogram', cascade="all, delete-orphan")
    )
    date = Column(Date, default=date.today(), nullable=False)
    medium = Column(Integer, nullable=False)
    high = Column(Integer, nullable=False)
    critical = Column(Integer, nullable=False)
    confirmed = Column(Integer, nullable=False)

    # This method is required by event :_(
    @property
    def parent(self):
        return


class VulnerabilityHitCount(db.Model):
    __tablename__ = "vulnerability_hit_count"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('vulnerability_hit_counts', cascade="all, delete-orphan")
    )
    date = Column(Date, nullable=False, default=datetime.utcnow())

    # Low
    low_open_unconfirmed = Column(Integer, nullable=False, default=0)
    low_open_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def low_open_total(self):
        return self.low_open_unconfirmed + self.low_open_confirmed

    low_risk_accepted_unconfirmed = Column(Integer, nullable=False, default=0)
    low_risk_accepted_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def low_risk_accepted_total(self):
        return self.low_risk_accepted_unconfirmed + self.low_risk_accepted_confirmed

    low_re_opened_unconfirmed = Column(Integer, nullable=False, default=0)
    low_re_opened_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def low_re_opened_total(self):
        return self.low_re_opened_unconfirmed + self.low_re_opened_confirmed

    low_closed_unconfirmed = Column(Integer, nullable=False, default=0)
    low_closed_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def low_closed_total(self):
        return self.low_closed_unconfirmed + self.low_closed_confirmed

    @hybrid_property
    def low_total(self):
        return self.low_open_total + self.low_risk_accepted_total + self.low_re_opened_total + self.low_closed_total

    @hybrid_property
    def low_confirmed_total(self):
        return self.low_open_confirmed + self.low_risk_accepted_confirmed + self.low_re_opened_confirmed + \
               self.low_closed_confirmed

    # Medium
    medium_open_unconfirmed = Column(Integer, nullable=False, default=0)
    medium_open_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def medium_open_total(self):
        return self.medium_open_unconfirmed + self.medium_open_confirmed

    medium_risk_accepted_unconfirmed = Column(Integer, nullable=False, default=0)
    medium_risk_accepted_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def medium_risk_accepted_total(self):
        return self.medium_risk_accepted_unconfirmed + self.medium_risk_accepted_confirmed

    medium_re_opened_unconfirmed = Column(Integer, nullable=False, default=0)
    medium_re_opened_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def medium_re_opened_total(self):
        return self.medium_re_opened_unconfirmed + self.medium_re_opened_confirmed

    medium_closed_unconfirmed = Column(Integer, nullable=False, default=0)
    medium_closed_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def medium_closed_total(self):
        return self.medium_closed_unconfirmed + self.medium_closed_confirmed

    @hybrid_property
    def medium_total(self):
        return self.medium_open_total + self.medium_risk_accepted_total + self.medium_re_opened_total + \
               self.medium_closed_total

    @hybrid_property
    def medium_confirmed_total(self):
        return self.medium_open_confirmed + self.medium_risk_accepted_confirmed + self.medium_re_opened_confirmed + \
               self.medium_closed_confirmed

    # High
    high_open_unconfirmed = Column(Integer, nullable=False, default=0)
    high_open_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def high_open_total(self):
        return self.high_open_unconfirmed + self.high_open_confirmed

    high_risk_accepted_unconfirmed = Column(Integer, nullable=False, default=0)
    high_risk_accepted_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def high_risk_accepted_total(self):
        return self.high_risk_accepted_unconfirmed + self.high_risk_accepted_confirmed

    high_re_opened_unconfirmed = Column(Integer, nullable=False, default=0)
    high_re_opened_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def high_re_opened_total(self):
        return self.high_re_opened_unconfirmed + self.high_re_opened_confirmed

    high_closed_unconfirmed = Column(Integer, nullable=False, default=0)
    high_closed_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def high_closed_total(self):
        return self.high_closed_unconfirmed + self.high_closed_confirmed

    @hybrid_property
    def high_total(self):
        return self.high_open_total + self.high_risk_accepted_total + self.high_re_opened_total + self.high_closed_total

    @hybrid_property
    def high_confirmed_total(self):
        return self.high_open_confirmed + self.high_risk_accepted_confirmed + self.high_re_opened_confirmed + \
               self.high_closed_confirmed

    # Critical
    critical_open_unconfirmed = Column(Integer, nullable=False, default=0)
    critical_open_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def critical_open_total(self):
        return self.critical_open_unconfirmed + self.critical_open_confirmed

    critical_risk_accepted_unconfirmed = Column(Integer, nullable=False, default=0)
    critical_risk_accepted_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def critical_risk_accepted_total(self):
        return self.critical_risk_accepted_unconfirmed + self.critical_risk_accepted_confirmed

    critical_re_opened_unconfirmed = Column(Integer, nullable=False, default=0)
    critical_re_opened_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def critical_re_opened_total(self):
        return self.critical_re_opened_unconfirmed + self.critical_re_opened_confirmed

    critical_closed_unconfirmed = Column(Integer, nullable=False, default=0)
    critical_closed_confirmed = Column(Integer, nullable=False, default=0)

    @hybrid_property
    def critical_closed_total(self):
        return self.critical_closed_unconfirmed + self.critical_closed_confirmed

    @hybrid_property
    def critical_total(self):
        return self.critical_open_total + self.critical_risk_accepted_total + self.critical_re_opened_total + \
               self.critical_closed_total

    @hybrid_property
    def critical_confirmed_total(self):
        return self.critical_open_confirmed + self.critical_risk_accepted_confirmed + \
               self.critical_re_opened_confirmed + self.critical_closed_confirmed

    # Specific for open status
    @hybrid_property
    def low_open_total_custom(self):
        return self.low_open_total + self.low_re_opened_total + self.low_risk_accepted_total

    @hybrid_property
    def low_open_confirmed_total_custom(self):
        return self.low_open_confirmed + self.low_re_opened_confirmed + self.low_risk_accepted_confirmed

    @hybrid_property
    def medium_open_total_custom(self):
        return self.medium_open_total + self.medium_re_opened_total + self.medium_risk_accepted_total

    @hybrid_property
    def medium_open_confirmed_total_custom(self):
        return self.medium_open_confirmed + self.medium_re_opened_confirmed + self.medium_risk_accepted_confirmed

    @hybrid_property
    def high_open_total_custom(self):
        return self.high_open_total + self.high_re_opened_total + self.high_risk_accepted_total

    @hybrid_property
    def high_open_confirmed_total_custom(self):
        return self.high_open_confirmed + self.high_re_opened_confirmed + self.high_risk_accepted_confirmed

    @hybrid_property
    def critical_open_total_custom(self):
        return self.critical_open_total + self.critical_re_opened_total + self.critical_risk_accepted_total

    @hybrid_property
    def critical_open_confirmed_total_custom(self):
        return self.critical_open_confirmed + self.critical_re_opened_confirmed + self.critical_risk_accepted_confirmed

    # total counts
    @hybrid_property
    def total(self):
        return self.low_total + self.medium_total + self.high_total + self.critical_total

    @hybrid_property
    def total_confirmed(self):
        return self.low_confirmed_total + self.medium_confirmed_total + self.high_confirmed_total + \
               self.critical_confirmed_total

    @hybrid_property
    def total_open(self):
        return self.low_open_total + self.medium_open_total + self.high_open_total + self.critical_open_total

    @hybrid_property
    def total_closed(self):
        return self.low_closed_total + self.medium_closed_total + self.high_closed_total + self.critical_closed_total

    @hybrid_property
    def total_re_opened(self):
        return self.low_re_opened_total + self.medium_re_opened_total + self.high_re_opened_total + \
               self.critical_re_opened_total

    @hybrid_property
    def total_risk_accepted(self):
        return self.low_risk_accepted_total + self.medium_risk_accepted_total + self.high_risk_accepted_total + \
               self.critical_risk_accepted_total

    @hybrid_property
    def total_open_confirmed(self):
        return self.low_open_confirmed + self.medium_open_confirmed + self.high_open_confirmed + \
               self.critical_open_confirmed

    @hybrid_property
    def total_closed_confirmed(self):
        return self.low_closed_confirmed + self.medium_closed_confirmed + self.high_closed_confirmed + \
               self.critical_closed_confirmed

    @hybrid_property
    def total_re_opened_confirmed(self):
        return self.low_re_opened_confirmed + self.medium_re_opened_confirmed + self.high_re_opened_confirmed + \
               self.critical_re_opened_confirmed

    @hybrid_property
    def total_risk_accepted_confirmed(self):
        return self.low_risk_accepted_confirmed + self.medium_risk_accepted_confirmed + \
               self.high_risk_accepted_confirmed + self.critical_risk_accepted_confirmed

    @hybrid_property
    def total_status(self):
        return self.total_open + self.total_closed + self.total_re_opened + self.total_risk_accepted

    @hybrid_property
    def total_status_confirmed(self):
        return self.total_open_confirmed + self.total_closed_confirmed + self.total_re_opened_confirmed + \
               self.total_risk_accepted_confirmed

    @hybrid_property
    def total_open_confirmed_total_custom(self):
        return self.critical_open_confirmed_total_custom + self.high_open_confirmed_total_custom + \
               self.medium_open_confirmed_total_custom + self.low_open_confirmed_total_custom

    @hybrid_property
    def total_open_total_custom(self):
        return self.critical_open_total_custom + self.high_open_total_custom + self.medium_open_total_custom + \
               self.low_open_total_custom

    @property
    def parent(self):
        return


class CustomAssociationSet(_AssociationSet):
    """
    A custom association set that passes the creator method the both
    the value and the instance of the parent object
    """

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

        super().__init__(lazy_collection, creator, getter, setter, parent)

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
                    # The session can hold elements without a name (although it shouldn't)
                    continue
                if conflict_obj.name == value:
                    continue
                persisted_conflict_obj = session.query(conflict_obj.__class__).filter_by(name=conflict_obj.name).first()
                if persisted_conflict_obj:
                    self.col.add(persisted_conflict_obj)
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


def _build_associationproxy_creator_non_workspaced(model_class_name, preprocess_value_func: Callable = None):
    def creator(name, vulnerability):
        """Get or create a reference/policyviolation/CVE with the
        corresponding name. This is not workspace aware"""

        # Ugly hack to avoid the fact that Reference is defined after
        # Vulnerability
        model_class = globals()[model_class_name]

        if preprocess_value_func:
            name = preprocess_value_func(name)

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
    shipped = Column(Boolean, nullable=False, default=False)

    # CVSS
    _cvss2_vector_string = Column(Text, nullable=True)

    @hybrid_property
    def cvss2_vector_string(self):
        return self._cvss2_vector_string

    @cvss2_vector_string.setter
    def cvss2_vector_string(self, vector_string):
        self._cvss2_vector_string = vector_string
        if not self._cvss2_vector_string:
            self.init_cvss2_attrs()
            return None
        try:
            cvss2 = cvss.CVSS2(vector_string)
        except Exception as e:
            logger.error(f"Error parsing CVSS2 vector string: {self._cvss2_vector_string}", e)

    def init_cvss2_attrs(self):
        self._cvss2_vector_string = None

    _cvss3_vector_string = Column(Text, nullable=True)

    @hybrid_property
    def cvss3_vector_string(self):
        return self._cvss3_vector_string

    @cvss3_vector_string.setter
    def cvss3_vector_string(self, vector_string):
        self._cvss3_vector_string = vector_string
        if not self._cvss3_vector_string:
            self.init_cvss3_attrs()
            return None
        try:
            cvss3 = cvss.CVSS3(vector_string)
        except Exception as e:
            logger.error(f"Error parsing CVSS3 vector string: {self._cvss3_vector_string}", e)

    def init_cvss3_attrs(self):
        self._cvss3_vector_string = None

    # CVE

    cve = Column(Text, nullable=True, default="")


class CommandObject(db.Model):
    __tablename__ = 'command_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)

    command = relationship('Command', backref='command_objects')
    command_id = Column(Integer, ForeignKey('command.id', ondelete='SET NULL'), index=True)

    # 1 workspace <--> N command_objects
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('command_objects', cascade="all, delete-orphan")
    )

    create_date = Column(DateTime, default=datetime.utcnow)

    # the following properties are used to know if the command created the specified objects_type
    # remember that this table has a row instances per relationship.
    # this created integer can be used to obtain the total object_type objects created.
    created = _make_command_created_related_object()

    # We are currently using the column property created. However, to avoid losing information
    # we also store a boolean to know if at the moment of created the object related to the
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
        co = cls(obj, workspace=command.workspace, command=command, created_persistent=True, **kwargs)
        if add_to_session:
            db.session.add(co)
        return co

    def __init__(self, object_=None, **kwargs):

        if object_ is not None:
            assert 'object_type' not in kwargs
            assert 'object_id' not in kwargs
            object_type = get_object_type_for(object_)

            # db.session.flush()
            assert object_.id is not None, "object must have an ID. Try flushing the session"
            kwargs['object_id'] = object_.id
            kwargs['object_type'] = object_type
        super().__init__(**kwargs)


def _make_created_objects_sum(object_type_filter):
    where_conditions = [f"command_object.object_type= '{object_type_filter}'",
                        "command_object.command_id = command.id",
                        "command_object.workspace_id = command.workspace_id"]
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
    where_conditions = [f"command_object.object_type= '{object_type_filter}'",
                        "command_object.command_id = command.id",
                        "vulnerability.id = command_object.object_id ",
                        "command_object.workspace_id = vulnerability.workspace_id"]
    for attr, filter_value in join_filters.items():
        where_conditions.append(f"vulnerability.{attr} = {filter_value}")
    return column_property(
        select([func.sum(CommandObject.created)]).
        select_from(table('command_object')).
        select_from(table('vulnerability')).
        where(text(' and '.join(where_conditions)))
    )


class Command(Metadata):
    IMPORT_SOURCE = [
        'report',
        # all the files the tools export and faraday imports it from the reports directory,
        # gtk manual import or web import.
        'shell',  # command executed on the shell or webshell with hooks connected to faraday.
        'agent',
        'cloud_agent'
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

    # 1 workspace <--> N commands
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('commands', cascade="all, delete-orphan")
    )
    warnings = Column(String(250), nullable=True)

    sum_created_vulnerabilities = _make_created_objects_sum('vulnerability')
    sum_created_vulnerabilities_web = _make_created_objects_sum_joined('vulnerability',
                                                                       {'type': '\'vulnerability_web\''})
    sum_created_hosts = _make_created_objects_sum('host')
    sum_created_services = _make_created_objects_sum('service')
    sum_created_vulnerability_critical = _make_created_objects_sum_joined('vulnerability', {'severity': '\'critical\''})
    sum_created_vulnerability_high = _make_created_objects_sum_joined('vulnerability', {'severity': '\'high\''})
    sum_created_vulnerability_medium = _make_created_objects_sum_joined('vulnerability', {'severity': '\'medium\''})
    sum_created_vulnerability_low = _make_created_objects_sum_joined('vulnerability', {'severity': '\'low\''})
    sum_created_vulnerability_info = _make_created_objects_sum_joined('vulnerability',
                                                                      {'severity': '\'informational\''})
    sum_created_vulnerability_unclassified = _make_created_objects_sum_joined('vulnerability',
                                                                              {'severity': '\'unclassified\''})

    agent_execution = relationship(
        'AgentExecution',
        uselist=False,
        back_populates="command"
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

    @property
    def service(self):
        if self.services:
            return self.services[0]
        else:
            return None

    # 1 workspace <--> N hosts
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref("hosts", cascade="all, delete-orphan", passive_deletes=True)
    )

    open_service_count = _make_generic_count_property('host', 'service', where=text("service.status = 'open'"))
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
        where(text('vulnerability.service_id = service.id and service.host_id = host.id')).
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

    vulnerability_critical_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_high_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_medium_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_low_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_info_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_unclassified_generic_count = Column(Integer, server_default=text("0"))

    importance = Column(Integer, default=0)

    risk = Column(Integer, default=0)

    @classmethod
    def query_with_count(cls, host_ids, workspace):
        query = cls.query.join(Workspace).filter(Workspace.id == workspace.id)
        if host_ids:
            query = query.filter(cls.id.in_(host_ids))
        return query.options(
            undefer(cls.credentials_count),
            undefer(cls.open_service_count),
            joinedload(cls.hostnames),
            joinedload(cls.services),
            joinedload(cls.update_user),
            joinedload(getattr(cls, 'creator')).load_only('username'),
        ).limit(None).offset(0)

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


cve_vulnerability_association = db.Table('cve_association',
                                         Column('vulnerability_id', Integer,
                                                db.ForeignKey('vulnerability.id', ondelete='CASCADE'), nullable=False),
                                         Column('cve_id', Integer, db.ForeignKey('cve.id'), nullable=False)
                                         )


class CVE(db.Model):
    __tablename__ = 'cve'

    CVE_PATTERN = r'CVE-\d{4}-\d{4,7}'

    id = Column(Integer, primary_key=True)
    name = Column(String(24), unique=True)
    year = Column(Integer, nullable=True)
    identifier = Column(Integer, nullable=True)

    # TODO: add customer inserted flag
    # Other fields TBD

    vulnerabilities = relationship("VulnerabilityGeneric", secondary=cve_vulnerability_association)

    def __str__(self):
        return f'{self.id}'

    def __init__(self, name=None, **kwargs):
        logger.debug(f'cve found {name}')
        try:
            name = name.upper()
            _, year, identifier = name.split("-")
            super().__init__(name=name, year=year, identifier=identifier, **kwargs)
        except ValueError as e:
            logger.error("Invalid cve format. Should be CVE-YEAR-ID.")
            raise ValueError("Invalid cve format. Should be CVE-YEAR-NUMBERID.") from e


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

    host_id = Column(Integer, ForeignKey('host.id', ondelete='CASCADE'), index=True, nullable=False)
    host = relationship(
        'Host',
        foreign_keys=[host_id],
    )

    # 1 workspace <--> N services
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('services', cascade="all, delete-orphan", passive_deletes=True),
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
        return f"({self.port}/{self.protocol}) {self.name}{version or ''}"


cwe_vulnerability_association = Table('cwe_vulnerability_association',
                                      db.Model.metadata,
                                      Column('cwe_id', Integer, ForeignKey('cwe.id', ondelete='CASCADE')),
                                      Column('vulnerability_id', Integer, ForeignKey('vulnerability.id',
                                                                                     ondelete='CASCADE'))
                                      )


owasp_vulnerability_association = Table('owasp_vulnerability_association',
                                        db.Model.metadata,
                                        Column('owasp_id', Integer, ForeignKey('owasp.id', ondelete='CASCADE')),
                                        Column('vulnerability_id', Integer, ForeignKey('vulnerability.id',
                                                                                       ondelete='CASCADE'))
                                        )


class VulnerabilityGeneric(VulnerabilityABC):
    STATUS_OPEN = 'open'
    STATUS_RE_OPENED = 're-opened'
    STATUS_CLOSED = 'closed'
    STATUS_RISK_ACCEPTED = 'risk-accepted'

    STATUSES = [
        STATUS_OPEN,
        STATUS_CLOSED,
        STATUS_RE_OPENED,
        STATUS_RISK_ACCEPTED
    ]
    VULN_TYPES = [
        'vulnerability',
        'vulnerability_web',
        'vulnerability_code'
    ]

    __tablename__ = 'vulnerability'
    id = Column(Integer, primary_key=True)
    _tmp_id = Column(Integer)
    confirmed = Column(Boolean, nullable=False, default=False)
    status = Column(Enum(*STATUSES, name='vulnerability_statuses'), nullable=False, default="open")
    type = Column(Enum(*VULN_TYPES, name='vulnerability_types'), nullable=False)
    issuetracker = BlankColumn(Text)
    association_date = Column(DateTime, nullable=True)
    disassociated_manually = Column(Boolean, nullable=False, default=False)
    tool = BlankColumn(Text, nullable=False)
    method = BlankColumn(Text)
    parameters = BlankColumn(Text)
    parameter_name = BlankColumn(Text)
    path = BlankColumn(Text)
    query_string = BlankColumn(Text)
    request = BlankColumn(Text)
    response = BlankColumn(Text)
    website = BlankColumn(Text)
    status_code = Column(Integer, nullable=True)
    epss = Column(Float, nullable=True)  # Exploit Prediction Scoring System (EPSS)

    vulnerability_duplicate_id = Column(
        Integer,
        ForeignKey('vulnerability.id', ondelete='SET NULL'),
        index=True,
        nullable=True,
    )
    duplicates_associated = relationship("VulnerabilityGeneric", cascade="all, delete-orphan",
                                         backref=backref('duplicates_main', remote_side=[id])
                                         )
    vulnerability_template_id = Column(
        Integer,
        ForeignKey('vulnerability_template.id', ondelete='SET NULL'),
        index=True,
        nullable=True,
    )

    vulnerability_template = relationship('VulnerabilityTemplate',
                                          backref=backref('duplicate_vulnerabilities', passive_deletes='all'))

    # 1 workspace <--> N vulnerabilities
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('vulnerabilities', cascade="all, delete-orphan", passive_deletes=True)
    )

    cve_instances = relationship("CVE",
                                 secondary=cve_vulnerability_association,
                                 collection_class=set)

    cve = association_proxy('cve_instances',
                            'name',
                            proxy_factory=CustomAssociationSet,
                            creator=_build_associationproxy_creator_non_workspaced('CVE', lambda c: c.upper()))

    refs = relationship(
        'VulnerabilityReference',
        cascade="all, delete-orphan",
        backref=backref("vulnerabilities")
    )

    _cvss2_vector_string = Column(Text, nullable=True)
    cvss2_base_score = Column(Float)
    cvss2_exploitability_score = Column(Float)
    cvss2_impact_score = Column(Float)
    cvss2_base_severity = Column(Text, nullable=True)
    cvss2_temporal_score = Column(Float)
    cvss2_temporal_severity = Column(Text, nullable=True)
    cvss2_environmental_score = Column(Float)
    cvss2_environmental_severity = Column(Text, nullable=True)
    cvss2_access_vector = Column(Text, nullable=True)
    cvss2_access_complexity = Column(Text, nullable=True)
    cvss2_authentication = Column(Text, nullable=True)
    cvss2_confidentiality_impact = Column(Text, nullable=True)
    cvss2_integrity_impact = Column(Text, nullable=True)
    cvss2_availability_impact = Column(Text, nullable=True)
    cvss2_exploitability = Column(Text, nullable=True)
    cvss2_remediation_level = Column(Text, nullable=True)
    cvss2_report_confidence = Column(Text, nullable=True)
    cvss2_collateral_damage_potential = Column(Text, nullable=True)
    cvss2_target_distribution = Column(Text, nullable=True)
    cvss2_confidentiality_requirement = Column(Text, nullable=True)
    cvss2_integrity_requirement = Column(Text, nullable=True)
    cvss2_availability_requirement = Column(Text, nullable=True)

    owasp = relationship('OWASP', secondary=owasp_vulnerability_association)

    @hybrid_property
    def cvss2_vector_string(self):
        return self._cvss2_vector_string

    @cvss2_vector_string.setter
    def cvss2_vector_string(self, vector_string):
        self._cvss2_vector_string = vector_string
        self.set_cvss2_attrs()

    def init_cvss2_attrs(self):
        self._cvss2_vector_string = None
        self.cvss2_base_score = None
        self.cvss2_base_severity = None
        self.cvss2_temporal_score = None
        self.cvss2_temporal_severity = None
        self.cvss2_environmental_score = None
        self.cvss2_environmental_severity = None
        self.cvss2_access_vector = None
        self.cvss2_access_complexity = None
        self.cvss2_authentication = None
        self.cvss2_confidentiality_impact = None
        self.cvss2_integrity_impact = None
        self.cvss2_availability_impact = None
        self.cvss2_exploitability = None
        self.cvss2_remediation_level = None
        self.cvss2_report_confidence = None
        self.cvss2_collateral_damage_potential = None
        self.cvss2_target_distribution = None
        self.cvss2_confidentiality_requirement = None
        self.cvss2_integrity_requirement = None
        self.cvss2_availability_requirement = None
        self.cvss2_exploitability_score = None
        self.cvss2_impact_score = None

    def set_cvss2_attrs(self):
        """
        Parse cvss2 and assign attributes
        """
        if not self.cvss2_vector_string:
            self.init_cvss2_attrs()
            return None
        try:
            cvss_instance = cvss.CVSS2(self.cvss2_vector_string)
            self.cvss2_base_score = get_base_score(cvss_instance)
            self.cvss2_base_severity = get_severity(cvss_instance, 'B')
            self.cvss2_temporal_score = get_temporal_score(cvss_instance)
            self.cvss2_temporal_severity = get_severity(cvss_instance, 'T')
            self.cvss2_environmental_score = get_environmental_score(cvss_instance)
            self.cvss2_environmental_severity = get_severity(cvss_instance, 'E')
            self.cvss2_access_vector = get_propper_value(cvss_instance, 'AV')
            self.cvss2_access_complexity = get_propper_value(cvss_instance, 'AC')
            self.cvss2_authentication = get_propper_value(cvss_instance, 'Au')
            self.cvss2_confidentiality_impact = get_propper_value(cvss_instance, 'C')
            self.cvss2_integrity_impact = get_propper_value(cvss_instance, 'I')
            self.cvss2_availability_impact = get_propper_value(cvss_instance, 'A')
            self.cvss2_exploitability = get_propper_value(cvss_instance, 'E')
            self.cvss2_remediation_level = get_propper_value(cvss_instance, 'RL')
            self.cvss2_report_confidence = get_propper_value(cvss_instance, 'RC')
            self.cvss2_collateral_damage_potential = get_propper_value(cvss_instance, 'CDP')
            self.cvss2_target_distribution = get_propper_value(cvss_instance, 'TD')
            self.cvss2_confidentiality_requirement = get_propper_value(cvss_instance, 'CR')
            self.cvss2_integrity_requirement = get_propper_value(cvss_instance, 'IR')
            self.cvss2_availability_requirement = get_propper_value(cvss_instance, 'AR')
            self.cvss2_exploitability_score = get_exploitability_score(cvss_instance)
            self.cvss2_impact_score = get_impact_score(cvss_instance)
        except Exception as e:
            logger.error("Could not parse cvss %s. %s", self.cvss2_vector_string, e)

    _cvss3_vector_string = Column(Text, nullable=True)
    cvss3_base_score = Column(Float)
    cvss3_exploitability_score = Column(Float)
    cvss3_impact_score = Column(Float)
    cvss3_base_severity = Column(Text, nullable=True)
    cvss3_temporal_score = Column(Float)
    cvss3_temporal_severity = Column(Text, nullable=True)
    cvss3_environmental_score = Column(Float)
    cvss3_environmental_severity = Column(Text, nullable=True)
    cvss3_attack_vector = Column(Text, nullable=True)
    cvss3_attack_complexity = Column(Text, nullable=True)
    cvss3_privileges_required = Column(Text, nullable=True)
    cvss3_user_interaction = Column(Text, nullable=True)
    cvss3_confidentiality_impact = Column(Text, nullable=True)
    cvss3_integrity_impact = Column(Text, nullable=True)
    cvss3_availability_impact = Column(Text, nullable=True)
    cvss3_exploit_code_maturity = Column(Text, nullable=True)
    cvss3_remediation_level = Column(Text, nullable=True)
    cvss3_report_confidence = Column(Text, nullable=True)
    cvss3_confidentiality_requirement = Column(Text, nullable=True)
    cvss3_integrity_requirement = Column(Text, nullable=True)
    cvss3_availability_requirement = Column(Text, nullable=True)
    cvss3_modified_attack_vector = Column(Text, nullable=True)
    cvss3_modified_attack_complexity = Column(Text, nullable=True)
    cvss3_modified_privileges_required = Column(Text, nullable=True)
    cvss3_modified_user_interaction = Column(Text, nullable=True)
    cvss3_modified_scope = Column(Text, nullable=True)
    cvss3_modified_confidentiality_impact = Column(Text, nullable=True)
    cvss3_modified_integrity_impact = Column(Text, nullable=True)
    cvss3_modified_availability_impact = Column(Text, nullable=True)
    cvss3_scope = Column(Text, nullable=True)

    @hybrid_property
    def cvss3_vector_string(self):
        return self._cvss3_vector_string

    @cvss3_vector_string.setter
    def cvss3_vector_string(self, vector_string):
        self._cvss3_vector_string = vector_string
        self.set_cvss3_attrs()

    def init_cvss3_attrs(self):
        self._cvss3_vector_string = None
        self.cvss3_base_score = None
        self.cvss3_base_severity = None
        self.cvss3_temporal_score = None
        self.cvss3_temporal_severity = None
        self.cvss3_environmental_score = None
        self.cvss3_environmental_severity = None
        self.cvss3_attack_vector = None
        self.cvss3_attack_complexity = None
        self.cvss3_privileges_required = None
        self.cvss3_user_interaction = None
        self.cvss3_scope = None
        self.cvss3_confidentiality_impact = None
        self.cvss3_integrity_impact = None
        self.cvss3_availability_impact = None
        self.cvss3_exploit_code_maturity = None
        self.cvss3_remediation_level = None
        self.cvss3_report_confidence = None
        self.cvss3_confidentiality_requirement = None
        self.cvss3_integrity_requirement = None
        self.cvss3_availability_requirement = None
        self.cvss3_modified_attack_vector = None
        self.cvss3_modified_attack_complexity = None
        self.cvss3_modified_privileges_required = None
        self.cvss3_modified_user_interaction = None
        self.cvss3_modified_scope = None
        self.cvss3_modified_confidentiality_impact = None
        self.cvss3_modified_integrity_impact = None
        self.cvss3_modified_availability_impact = None
        self.cvss3_exploitability_score = None
        self.cvss3_impact_score = None

    def set_cvss3_attrs(self):
        """
        Parse cvss2 and assign attributes
        """
        if not self.cvss3_vector_string:
            self.init_cvss3_attrs()
            return None

        try:
            cvss_instance = cvss.CVSS3(self.cvss3_vector_string)
            self.cvss3_base_score = get_base_score(cvss_instance)
            self.cvss3_base_severity = get_severity(cvss_instance, 'B')
            self.cvss3_temporal_score = get_temporal_score(cvss_instance)
            self.cvss3_temporal_severity = get_severity(cvss_instance, 'T')
            self.cvss3_environmental_score = get_environmental_score(cvss_instance)
            self.cvss3_environmental_severity = get_severity(cvss_instance, 'E')
            self.cvss3_attack_vector = get_propper_value(cvss_instance, 'AV')
            self.cvss3_attack_complexity = get_propper_value(cvss_instance, 'AC')
            self.cvss3_privileges_required = get_propper_value(cvss_instance, 'PR')
            self.cvss3_user_interaction = get_propper_value(cvss_instance, 'UI')
            self.cvss3_scope = get_propper_value(cvss_instance, 'S')
            self.cvss3_confidentiality_impact = get_propper_value(cvss_instance, 'C')
            self.cvss3_integrity_impact = get_propper_value(cvss_instance, 'I')
            self.cvss3_availability_impact = get_propper_value(cvss_instance, 'A')
            self.cvss3_exploit_code_maturity = get_propper_value(cvss_instance, 'E')
            self.cvss3_remediation_level = get_propper_value(cvss_instance, 'RL')
            self.cvss3_report_confidence = get_propper_value(cvss_instance, 'RC')
            self.cvss3_confidentiality_requirement = get_propper_value(cvss_instance, 'CR')
            self.cvss3_integrity_requirement = get_propper_value(cvss_instance, 'IR')
            self.cvss3_availability_requirement = get_propper_value(cvss_instance, 'AR')
            self.cvss3_modified_attack_vector = get_propper_value(cvss_instance, 'MAV')
            self.cvss3_modified_attack_complexity = get_propper_value(cvss_instance, 'MAC')
            self.cvss3_modified_privileges_required = get_propper_value(cvss_instance, 'MPR')
            self.cvss3_modified_user_interaction = get_propper_value(cvss_instance, 'MUI')
            self.cvss3_modified_scope = get_propper_value(cvss_instance, 'MS')
            self.cvss3_modified_confidentiality_impact = get_propper_value(cvss_instance, 'MC')
            self.cvss3_modified_integrity_impact = get_propper_value(cvss_instance, 'MI')
            self.cvss3_modified_availability_impact = get_propper_value(cvss_instance, 'MA')
            self.cvss3_exploitability_score = get_exploitability_score(cvss_instance)
            self.cvss3_impact_score = get_impact_score(cvss_instance)
        except Exception as e:
            logger.error("Could not parse cvss %s. %s", self.cvss3_vector_string, e)

    cwe = relationship('CWE', secondary=cwe_vulnerability_association)

    reference_instances = relationship(
        "Reference",
        secondary="reference_vulnerability_association",
        collection_class=set
    )

    references = association_proxy(
        'reference_instances', 'name',
        proxy_factory=CustomAssociationSet,
        creator=_build_associationproxy_creator('Reference'))

    policy_violation_instances = relationship(
        "PolicyViolation",
        secondary="policy_violation_vulnerability_association",
        collection_class=set
    )

    policy_violations = association_proxy(
        'policy_violation_instances', 'name',
        proxy_factory=CustomAssociationSet,
        creator=_build_associationproxy_creator('PolicyViolation'))

    evidence = relationship(
        "File",
        primaryjoin="and_(File.object_id==VulnerabilityGeneric.id, File.object_type=='vulnerability')",
        foreign_keys="File.object_id",
        cascade="all, delete-orphan"
    )

    tags = relationship(
        "Tag",
        secondary="tag_object",
        primaryjoin="and_(TagObject.object_id==VulnerabilityGeneric.id, TagObject.object_type=='vulnerability')",
        collection_class=set,
    )

    creator_command_id = column_property(
        select([CommandObject.command_id]).
        where(CommandObject.object_type == 'vulnerability').
        where(text('command_object.object_id = vulnerability.id')).
        where(CommandObject.workspace_id == workspace_id).
        order_by(asc(CommandObject.create_date)).
        limit(1),
        deferred=True)

    creator_command_tool = column_property(
        select([Command.tool]).
        select_from(join(Command, CommandObject, Command.id == CommandObject.command_id)).
        where(CommandObject.object_type == 'vulnerability').
        where(text('command_object.object_id = vulnerability.id')).
        where(CommandObject.workspace_id == workspace_id).
        order_by(asc(CommandObject.create_date)).
        limit(1),
        deferred=True
    )

    _host_ip_query = (
        select([Host.ip]).
        where(text('vulnerability.host_id = host.id'))
    )
    _service_ip_query = (
        select([text('host_inner.ip')]).
        select_from(text('host as host_inner, service')).
        where(text('vulnerability.service_id = service.id and host_inner.id = service.host_id'))
    )
    target_host_ip = column_property(
        case([
            (text('vulnerability.host_id IS NOT null'), _host_ip_query.as_scalar()),
            (text('vulnerability.service_id IS NOT null'), _service_ip_query.as_scalar())
        ]),
        deferred=True
    )

    _host_os_query = (
        select([Host.os]).
        where(text('vulnerability.host_id = host.id'))
    )
    _service_os_query = (
        select([text('host_inner.os')]).
        select_from(text('host as host_inner, service')).
        where(text('vulnerability.service_id = service.id and host_inner.id = service.host_id'))
    )

    host_id = Column(Integer, ForeignKey(Host.id, ondelete='CASCADE'), index=True)
    host = relationship(
        'Host',
        backref=backref("vulnerabilities", cascade="all, delete-orphan"),
        foreign_keys=[host_id],
    )

    @declared_attr
    def service_id(self):
        return Column(Integer, db.ForeignKey('service.id', ondelete='CASCADE'), index=True)

    target_host_os = column_property(
        case([
            (text('vulnerability.host_id IS NOT null'), _host_os_query.as_scalar()),
            (text('vulnerability.service_id IS NOT null'), _service_os_query.as_scalar())
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

    @property
    def has_duplicate(self):
        return self.vulnerability_duplicate_id is None

    @property
    def hostnames(self):
        if self.host is not None:
            return self.host.hostnames
        elif self.service is not None:
            return self.service.host.hostnames
        raise ValueError("Vulnerability has no service nor host")

    @declared_attr
    def service(self):
        return relationship('Service', backref=backref("vulnerabilitiesGeneric", cascade="all, delete-orphan"))


class Vulnerability(VulnerabilityGeneric):
    __tablename__ = None

    @declared_attr
    def service_id(self):
        return VulnerabilityGeneric.__table__.c.get('service_id',
                                                    Column(Integer,
                                                           db.ForeignKey('service.id', ondelete='CASCADE'),
                                                           index=True))

    @declared_attr
    def service(self):
        return relationship('Service', backref=backref("vulnerabilities", cascade="all, delete-orphan"))

    @property
    def parent(self):
        return self.host or self.service

    __mapper_args__ = {
        'polymorphic_identity': VulnerabilityGeneric.VULN_TYPES[0]
    }


class VulnerabilityWeb(VulnerabilityGeneric):
    __tablename__ = None

    def __init__(self, *args, **kwargs):
        # Sanitize some fields on creation
        if 'request' in kwargs:
            kwargs['request'] = ''.join([x for x in kwargs['request'] if x in string.printable])
        if 'response' in kwargs:
            kwargs['response'] = ''.join([x for x in kwargs['response'] if x in string.printable])
        super().__init__(*args, **kwargs)

    @declared_attr
    def service_id(self):
        return VulnerabilityGeneric.__table__.c.get(
            'service_id', Column(Integer, db.ForeignKey('service.id', ondelete='CASCADE'),
                                 nullable=False))

    @declared_attr
    def service(self):
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

    source_code_id = Column(Integer, ForeignKey(SourceCode.id, ondelete='CASCADE'), index=True)
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
        super().__init__(name=name, **kwargs)


class Reference(Metadata):
    __tablename__ = 'reference'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)
    type = Column(Enum(*REFERENCE_TYPES, name='reference_types'), default='other')

    # 1 workspace <--> N references
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref("references", cascade="all, delete-orphan"),
    )

    __table_args__ = (
        UniqueConstraint('name', 'type', 'workspace_id',
                         name='uix_reference_name_type_vulnerability_workspace'),
    )

    def __init__(self, name=None, workspace_id=None, **kwargs):
        super().__init__(name=name, workspace_id=workspace_id, **kwargs)

    def __str__(self):
        return f'{self.name}'

    @property
    def parent(self):
        # TODO: fix this property
        return


class VulnerabilityReference(Metadata):
    __tablename__ = 'vulnerability_reference'
    __table_args__ = (
        UniqueConstraint('name', 'type', 'vulnerability_id', name='uix_vulnerability_reference_table_vuln_id_name_type'),
    )
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)
    type = Column(Enum(*REFERENCE_TYPES, name='reference_types'), default='other')

    vulnerability_id = Column(Integer, ForeignKey('vulnerability.id', ondelete="CASCADE"), nullable=False)

    def __str__(self):
        return f'{self.name}'

    @property
    def parent(self):
        # TODO: fix this property
        return


class OWASP(Metadata):
    __tablename__ = 'owasp'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text, unique=True)

    vulnerabilities = relationship('VulnerabilityWeb', secondary=owasp_vulnerability_association)


class ReferenceVulnerabilityAssociation(db.Model):
    __tablename__ = 'reference_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability.id', ondelete="CASCADE"), primary_key=True)
    reference_id = Column(Integer, ForeignKey('reference.id', ondelete="CASCADE"), primary_key=True)

    reference = relationship("Reference",
                             backref=backref("reference_associations", cascade="all, delete-orphan"),
                             foreign_keys=[reference_id])
    vulnerability = relationship("Vulnerability",
                                 backref=backref("reference_vulnerability_associations", cascade="all, delete-orphan"),
                                 foreign_keys=[vulnerability_id])


class PolicyViolationVulnerabilityAssociation(db.Model):
    __tablename__ = 'policy_violation_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability.id', ondelete="CASCADE"), primary_key=True)
    policy_violation_id = Column(Integer, ForeignKey('policy_violation.id', ondelete="CASCADE"), primary_key=True)

    policy_violation = relationship("PolicyViolation",
                                    backref=backref("policy_violation_associations", cascade="all, delete-orphan"),
                                    foreign_keys=[policy_violation_id])
    vulnerability = relationship("Vulnerability",
                                 backref=backref("policy_violation_vulnerability_associations",
                                                 cascade="all, delete-orphan"),
                                 foreign_keys=[vulnerability_id])


class ReferenceTemplateVulnerabilityAssociation(db.Model):
    __tablename__ = 'reference_template_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability_template.id', ondelete='CASCADE'), primary_key=True)
    reference_id = Column(Integer, ForeignKey('reference_template.id'), primary_key=True)

    reference = relationship(
        "ReferenceTemplate",
        foreign_keys=[reference_id],
        backref=backref('reference_template_associations', cascade="all, delete-orphan")
    )
    vulnerability = relationship(
        "VulnerabilityTemplate",
        foreign_keys=[vulnerability_id],
        backref=backref('reference_template_vulnerability_associations', cascade="all, delete-orphan")
    )


class PolicyViolationTemplateVulnerabilityAssociation(db.Model):
    __tablename__ = 'policy_violation_template_vulnerability_association'

    vulnerability_id = Column(Integer, ForeignKey('vulnerability_template.id', ondelete='CASCADE'), primary_key=True)
    policy_violation_id = Column(Integer, ForeignKey('policy_violation_template.id'), primary_key=True)

    policy_violation = relationship("PolicyViolationTemplate",
                                    backref=backref("policy_violation_template_associations",
                                                    cascade="all, delete-orphan"),
                                    foreign_keys=[policy_violation_id])
    vulnerability = relationship("VulnerabilityTemplate",
                                 backref=backref("policy_violation_template_vulnerability_associations",
                                                 cascade="all, delete-orphan"),
                                 foreign_keys=[vulnerability_id])


class PolicyViolationTemplate(Metadata):
    __tablename__ = 'policy_violation_template'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    __table_args__ = (
        UniqueConstraint('name', name='uix_policy_violation_template_name'),
    )

    def __init__(self, name=None, **kwargs):
        super().__init__(name=name, **kwargs)


class PolicyViolation(Metadata):
    __tablename__ = 'policy_violation'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    workspace_id = Column(
        Integer,
        ForeignKey('workspace.id', ondelete='CASCADE'),
        index=True,
        nullable=False
    )
    workspace = relationship(
        'Workspace',
        backref=backref("policy_violations", cascade="all, delete-orphan"),
        foreign_keys=[workspace_id],
    )

    __table_args__ = (
        UniqueConstraint('name', 'workspace_id', name='uix_policy_violation_template_name_vulnerability_workspace'),
    )

    def __init__(self, name=None, workspace_id=None, **kwargs):
        super().__init__(name=name, workspace_id=workspace_id, **kwargs)

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

    host_id = Column(Integer, ForeignKey(Host.id, ondelete='CASCADE'), index=True, nullable=True)
    host = relationship('Host',
                        backref=backref("credentials", cascade="all, delete-orphan"),
                        foreign_keys=[host_id])

    service_id = Column(Integer, ForeignKey(Service.id, ondelete='CASCADE'), index=True, nullable=True)
    service = relationship('Service',
                           backref=backref('credentials', cascade="all, delete-orphan"),
                           foreign_keys=[service_id])

    # 1 workspace <--> N credentials
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship('Workspace',
                             backref=backref('credentials', cascade="all, delete-orphan", passive_deletes=True),
                             foreign_keys=[workspace_id])

    _host_ip_query = (
        select([Host.ip]).
        where(text('credential.host_id = host.id'))
    )

    _service_ip_query = (
        select([text('host_inner.ip || \'/\' || service.name')]).
        select_from(text('host as host_inner, service')).
        where(text('credential.service_id = service.id and host_inner.id = service.host_id'))
    )

    target_ip = column_property(
        case([
            (text('credential.host_id IS NOT null'), _host_ip_query.as_scalar()),
            (text('credential.service_id IS NOT null'), _service_ip_query.as_scalar())
        ]),
        deferred=True
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


association_workspace_and_users_table = Table(
    'workspace_permission_association',
    db.Model.metadata,
    Column('workspace_id', Integer, ForeignKey('workspace.id', ondelete='CASCADE')),
    Column('user_id', Integer, ForeignKey('faraday_user.id'))
)


executive_report_workspace_table = Table(
    "executive_report_workspace_table",
    db.Model.metadata,
    Column("workspace_id", Integer, ForeignKey("workspace.id")),
    Column("executive_report_id", Integer, ForeignKey("executive_report.id")),
)


def _return_last_30_days() -> list:
    today = date.today()
    last_30_days = [today - timedelta(days=i) for i in range(30)]
    last_30_days = [day.isoformat() for day in last_30_days]
    return last_30_days


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
    risk_history_total = Column(JSONType(), nullable=False, default=[{"date": day, "risk": 0} for day in _return_last_30_days()])
    risk_history_avg = Column(JSONType(), nullable=False, default=[{"date": day, "risk": 0} for day in _return_last_30_days()])

    credential_count = _make_generic_count_property('workspace', 'credential')
    host_count = _make_generic_count_property('workspace', 'host')
    open_service_count = _make_generic_count_property('workspace', 'service', where=text("service.status = 'open'"))
    total_service_count = _make_generic_count_property('workspace', 'service')

    # Stats
    # By vuln type
    vulnerability_web_count = query_expression(literal(0))
    vulnerability_code_count = query_expression(literal(0))
    vulnerability_standard_count = query_expression(literal(0))
    # By vuln status
    vulnerability_open_count = query_expression(literal(0))
    vulnerability_re_opened_count = query_expression(literal(0))
    vulnerability_risk_accepted_count = query_expression(literal(0))
    vulnerability_closed_count = query_expression(literal(0))
    # By other
    vulnerability_confirmed_count = query_expression(literal(0))
    last_run_agent_date = query_expression()
    vulnerability_total_count = query_expression(literal(0))

    vulnerability_high_count = query_expression(literal(0))
    vulnerability_critical_count = query_expression(literal(0))
    vulnerability_medium_count = query_expression(literal(0))
    vulnerability_low_count = query_expression(literal(0))
    vulnerability_informational_count = query_expression(literal(0))
    vulnerability_unclassified_count = query_expression(literal(0))

    importance = Column(Integer, default=0)

    reports = relationship(
        'ExecutiveReport',
        secondary=executive_report_workspace_table,
        back_populates='workspaces',
        cascade='delete'
    )

    allowed_users = relationship(
        'User',
        secondary=association_workspace_and_users_table,
        back_populates="workspaces"
    )

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
                (SELECT executor.last_run
                    FROM executor
                    JOIN agent_execution ON executor.id = agent_execution.executor_id
                    WHERE executor.last_run is not null and
                    agent_execution.workspace_id = workspace.id
                    ORDER BY agent_execution.create_date DESC
                    LIMIT 1
                ) AS last_run_agent_date,
                p_4.count_3 as open_services,
                p_4.count_4 as total_service_count,
                p_5.count_5 as vulnerability_web_count,
                p_5.count_6 as vulnerability_code_count,
                p_5.count_7 as vulnerability_standard_count,
                p_5.count_8 as vulnerability_total_count,
                p_5.count_9 as vulnerability_critical_count,
                p_5.count_10 as vulnerability_high_count,
                p_5.count_11 as vulnerability_medium_count,
                p_5.count_12 as vulnerability_low_count,
                p_5.count_13 as vulnerability_informational_count,
                p_5.count_14 as vulnerability_unclassified_count,
                p_5.count_15 as vulnerability_open_count,
                p_5.count_16 as vulnerability_confirmed_count,
                p_5.count_17 as vulnerability_closed_count,
                p_5.count_18 as vulnerability_web_confirmed_count,
                p_5.count_19 as vulnerability_web_closed_count,
                p_5.count_20 as vulnerability_confirmed_and_not_closed_count,
                p_5.count_21 as vulnerability_web_confirmed_and_not_closed_count,
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
            LEFT JOIN (SELECT w.id as wid,
             COUNT(case when service.id IS NOT NULL and service.status = 'open' then 1 else null end) as count_3,
              COUNT(case when service.id IS NOT NULL then 1 else null end) AS count_4
                    FROM service
                    RIGHT JOIN workspace w ON service.workspace_id = w.id
                    GROUP BY w.id
                ) AS p_4 ON p_4.wid = workspace.id
            LEFT JOIN (SELECT w.id as w_id,
             COUNT(case when vulnerability.type = 'vulnerability_web' then 1 else null end) as count_5,
             COUNT(case when vulnerability.type = 'vulnerability_code' then 1 else null end) AS count_6,
             COUNT(case when vulnerability.type = 'vulnerability' then 1 else null end) as count_7,
             COUNT(case when vulnerability.id IS NOT NULL then 1 else null end) AS count_8,
             COUNT(case when vulnerability.severity = 'critical' then 1 else null end) as count_9,
             COUNT(case when vulnerability.severity = 'high' then 1 else null end) as count_10,
             COUNT(case when vulnerability.severity = 'medium' then 1 else null end) as count_11,
             COUNT(case when vulnerability.severity = 'low' then 1 else null end) as count_12,
             COUNT(case when vulnerability.severity = 'informational' then 1 else null end) as count_13,
             COUNT(case when vulnerability.severity = 'unclassified' then 1 else null end) as count_14,
             COUNT(case when vulnerability.status = 'open' OR vulnerability.status='re-opened' then 1 else null end) as count_15,
             COUNT(case when vulnerability.confirmed is True then 1 else null end) as count_16,
             COUNT(case when vulnerability.status = 'closed' then 1 else null end) as count_17,
             COUNT(case when vulnerability.type = 'vulnerability_web' AND vulnerability.confirmed is True then 1 else null end) as count_18,
             COUNT(case when vulnerability.type = 'vulnerability_web' AND vulnerability.status = 'closed' then 1 else null end) as count_19,
             COUNT(case when vulnerability.confirmed is True AND vulnerability.status != 'closed' then 1 else null end) as count_20,
             COUNT(case when vulnerability.type = 'vulnerability_web' AND vulnerability.confirmed is True AND vulnerability.status != 'closed' then 1 else null end) as count_21
                    FROM vulnerability
                    RIGHT JOIN workspace w ON vulnerability.workspace_id = w.id
                    WHERE 1=1 {0}
                    GROUP BY w.id
                ) AS p_5 ON p_5.w_id = workspace.id
        """
        concat_func = 'group_concat' if db.engine.dialect.name == 'sqlite' else 'string_agg'
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
        # query += " GROUP BY workspace.id "
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
        ForeignKey('workspace.id', ondelete='CASCADE'),
        index=True,
        nullable=False
    )

    workspace = relationship(
        'Workspace',
        backref=backref('scope', cascade="all, delete-orphan"),
        foreign_keys=[workspace_id],
    )

    __table_args__ = (
        UniqueConstraint('name', 'workspace_id', name='uix_scope_name_workspace'),
    )

    @property
    def parent(self):
        return


class WorkspacePermission(db.Model):
    __tablename__ = "workspace_permission_association"
    __table_args__ = {'extend_existing': True}
    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), nullable=False)
    workspace = relationship('Workspace')

    user_id = Column(Integer, ForeignKey('faraday_user.id'), nullable=False)
    user = relationship('User', foreign_keys=[user_id])

    @property
    def parent(self):
        return


def get(workspace_name):
    return db.session.query(Workspace).filter_by(name=workspace_name).first()


roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('faraday_user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('faraday_role.id')))


class Role(db.Model, RoleMixin):
    __tablename__ = 'faraday_role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    weight = db.Column(db.Integer(), nullable=False)


class UserToken(Metadata):
    __tablename__ = 'user_token'
    GITLAB_SCOPE = 'gitlab'
    SCOPES = [GITLAB_SCOPE]

    id = Column(Integer(), primary_key=True)

    user_id = Column(Integer, ForeignKey('faraday_user.id', ondelete='CASCADE'), index=True, nullable=False)
    user = relationship('User',
                        backref=backref('user_tokens', cascade="all, delete-orphan", passive_deletes=True),
                        foreign_keys=[user_id])

    token = Column(String(), nullable=False, unique=True)
    alias = Column(String(), nullable=False)
    expires_at = Column(DateTime(), nullable=True)
    scope = Column(Enum(*SCOPES, name='token_scopes'), nullable=False, default="gitlab")
    revoked = Column(Boolean(), default=False, nullable=False)
    hide = Column(Boolean(), default=False, nullable=False)

    @hybrid_property
    def expired(self):
        return self.expires_at is not None and self.expires_at < datetime.utcnow()

    @expired.expression
    def expired(cls):
        return case(
            [
                (cls.expires_at != None, cls.expires_at < datetime.utcnow())  # noqa E711
            ],
            else_=False
        )


class User(db.Model, UserMixin):
    __tablename__ = 'faraday_user'
    ADMIN_ROLE = 'admin'
    PENTESTER_ROLE = 'pentester'
    ASSET_OWNER_ROLE = 'asset_owner'
    CLIENT_ROLE = 'client'
    ROLES = [ADMIN_ROLE, PENTESTER_ROLE, ASSET_OWNER_ROLE, CLIENT_ROLE]
    OTP_STATES = ["disabled", "requested", "confirmed"]
    USER_TYPES = [LDAP_TYPE, LOCAL_TYPE, SAML_TYPE]

    id = Column(Integer, primary_key=True)
    username = NonBlankColumn(String(255), unique=True)
    password = Column(String(255), nullable=True)
    email = Column(String(255), unique=True, nullable=True)  # TBI
    name = BlankColumn(String(255))  # TBI
    last_login_at = Column(DateTime())  # flask-security
    current_login_at = Column(DateTime())  # flask-security
    last_login_ip = BlankColumn(String(100))  # flask-security
    current_login_ip = BlankColumn(String(100))  # flask-security
    login_count = Column(Integer)  # flask-security
    active = Column(Boolean(), default=True, nullable=False)  # TBI flask-security
    confirmed_at = Column(DateTime())
    _otp_secret = Column(
        String(32),
        name="otp_secret", nullable=True
    )
    state_otp = Column(Enum(*OTP_STATES, name='user_otp_states'), nullable=False, default="disabled")
    preferences = Column(JSONType, nullable=True, default={})
    fs_uniquifier = Column(String(64), unique=True, nullable=False)  # flask-security

    roles = db.relationship('Role', secondary=roles_users, backref='users')
    user_type = Column(Enum(*USER_TYPES, name='user_types'), nullable=False, default=LOCAL_TYPE)

    @property
    def roles_list(self):
        return [role.name for role in self.roles]

    workspaces = relationship(
        'Workspace',
        secondary=association_workspace_and_users_table,
        back_populates="allowed_users",
    )

    def __repr__(self):
        return f"<{'LDAP ' if self.user_type == LDAP_TYPE else ''}User: {self.username}>"

    def get_security_payload(self):
        return {
            "username": self.username,
            "name": self.username,
            "email": self.email,
            "roles": self.roles_list,
        }

    def get_token(self):
        user_id = self.fs_uniquifier
        hashed_data = hash_data(self.password) if self.password else None
        iat = int(time.time())
        exp = iat + int(faraday_server.api_token_expiration)
        jwt_data = {'user_id': user_id, "validation_check": hashed_data, 'iat': iat, 'exp': exp}

        return jwt.encode(jwt_data, app.config['SECRET_KEY'], algorithm="HS512")


class File(Metadata):
    __tablename__ = 'file'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = BlankColumn(Text)  # TODO migration: check why blank is allowed
    filename = NonBlankColumn(Text)
    description = BlankColumn(Text)
    content = Column(UploadedFileField(upload_type=FaradayUploadedFile), nullable=False)  # plain attached file
    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)


class UserAvatar(Metadata):
    __tablename__ = 'user_avatar'

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
        ForeignKey('methodology_template.id', ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    # 1 workspace <--> N methodologies
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('methodologies', cascade="all, delete-orphan"),
    )

    @property
    def parent(self):
        return


project_task_user_association = db.Table('project_task_user_association',
                                         db.Column('task_id', db.Integer(), db.ForeignKey('project_task.id')),
                                         db.Column('user_id', db.Integer(),
                                                   db.ForeignKey('faraday_user.id', ondelete='CASCADE'))
                                         )

task_dependencies_association = db.Table('task_dependencies_association',
                                         db.Column('task_id', db.Integer(), db.ForeignKey('project_task.id')),
                                         db.Column('task_dependency_id', db.Integer(),
                                                   db.ForeignKey('project_task.id', ondelete='CASCADE'))
                                         )

vulnerabilities_related_association = db.Table('vulnerabilities_related_association',
                                               db.Column('task_id', db.Integer(),
                                                         db.ForeignKey('project_task.id'),
                                                         primary_key=True),
                                               db.Column('vulnerability_id', db.Integer(),
                                                         db.ForeignKey('vulnerability.id', ondelete='CASCADE'),
                                                         primary_key=True))


class PlannerProject(Metadata):
    __tablename__ = 'planner_project'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    @property
    def parent(self):
        return

    @property
    def start_date(self):
        if self.tasks:
            if all(x.type == 'milestone' for x in self.tasks):
                return None
            return min(x.start_date for x in self.tasks if x.start_date is not None)

    @property
    def end_date(self):
        if self.tasks:
            return max(x.end_date for x in self.tasks if x.end_date is not None)


class ProjectTask(Metadata):

    TASK_STATUS_NEW = 'new'
    TASK_STATUS_REVIEW = 'review'
    TASK_STATUS_COMPLETED = 'completed'
    TASK_STATUS_IN_PROGRESS = 'in progress'

    STATUSES = [
        TASK_STATUS_NEW,
        TASK_STATUS_REVIEW,
        TASK_STATUS_COMPLETED,
        TASK_STATUS_IN_PROGRESS,
    ]

    NORMAL_TASK = 'task'
    MILESTONE = 'milestone'

    TASK_TYPES = [
        NORMAL_TASK,
        MILESTONE
    ]

    __tablename__ = 'project_task'
    id = Column(Integer, primary_key=True)

    name = Column(String, nullable=False, default='')
    description = Column(String, nullable=True)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    status = Column(Enum(*STATUSES, name='project_task_statuses'), nullable=True)
    type = Column(Enum(*TASK_TYPES, name='project_task_types'), nullable=False)

    users_assigned = relationship(
        "User",
        secondary="project_task_user_association")

    task_dependencies = relationship(
        "ProjectTask",
        secondary="task_dependencies_association",
        primaryjoin=id == task_dependencies_association.c.task_id,
        secondaryjoin=id == task_dependencies_association.c.task_dependency_id
    )

    vulnerabilities_related = relationship(
        "VulnerabilityGeneric",
        secondary="vulnerabilities_related_association",
    )

    project_id = Column(
        Integer,
        ForeignKey('planner_project.id'),
        index=True,
        nullable=False,
    )
    project = relationship(
        'PlannerProject',
        backref=backref('tasks', cascade="all, delete-orphan")
    )

    @property
    def parent(self):
        return None


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


class CWE(Metadata):
    __tablename__ = 'cwe'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text, unique=True)

    vulnerabilities = relationship('Vulnerability', secondary=cwe_vulnerability_association)


class Comment(Metadata):
    __tablename__ = 'comment'
    id = Column(Integer, primary_key=True)
    comment_type = Column(Enum(*COMMENT_TYPES, name='comment_types'), nullable=False, default='user')

    text = BlankColumn(Text)

    reply_to_id = Column(Integer, ForeignKey('comment.id', ondelete='SET NULL'))
    reply_to = relationship(
        'Comment',
        remote_side=[id],
        foreign_keys=[reply_to_id]
    )

    # 1 workspace <--> N comments
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=True)
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
    duplicate_detection = Column(Boolean, default=False, nullable=False)
    border_size = Column(Integer, default=3, nullable=True)
    advanced_filter = Column(Boolean, default=False, nullable=False)
    advanced_filter_parsed = Column(Text, nullable=False, default="")

    workspaces = relationship(
        'Workspace',
        secondary=executive_report_workspace_table,
        back_populates='reports'
    )
    tags = relationship(
        "Tag",
        secondary="tag_object",
        primaryjoin="and_(TagObject.object_id==ExecutiveReport.id, TagObject.object_type=='executive_report')",
        collection_class=set,
    )
    filter = Column(JSONType, nullable=True, default=[])

    @property
    def parent(self):
        return

    @property
    def attachments(self):
        return db.session.query(File).filter_by(
            object_id=self.id,
            object_type='executive_report'
        )


class ObjectType(db.Model):
    __tablename__ = 'object_type'
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)


class EventType(db.Model):
    __tablename__ = 'event_type'
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    async_event = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)


allowed_roles_association = db.Table('notification_allowed_roles',
                                     Column('notification_subscription_id', Integer,
                                            db.ForeignKey('notification_subscription.id'), nullable=False),
                                     Column('allowed_role_id', Integer, db.ForeignKey('faraday_role.id'),
                                            nullable=False)
                                     )


class NotificationSubscription(Metadata):
    __tablename__ = 'notification_subscription'
    id = Column(Integer, primary_key=True)
    event_type_id = Column(Integer, ForeignKey('event_type.id'), index=True, nullable=False)
    event_type = relationship(
        'EventType',
        backref=backref('event_type', cascade="all, delete-orphan")
    )
    allowed_roles = relationship("Role", secondary=allowed_roles_association)


class NotificationSubscriptionConfigBase(db.Model):
    __tablename__ = 'notification_subscription_config_base'
    id = Column(Integer, primary_key=True)
    subscription_id = Column(Integer, ForeignKey('notification_subscription.id'), index=True, nullable=False)
    subscription = relationship(
        'NotificationSubscription',
        backref=backref('notification_subscription_config', cascade="all, delete-orphan")
    )

    role_level = Column(Boolean, default=False)
    workspace_level = Column(Boolean, default=False)

    active = Column(Boolean, default=True)
    type = Column(String(24))

    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }

    __table_args__ = (
        UniqueConstraint('subscription_id', 'type', name='uix_subscriptionid_type'),
    )

    @property
    def dst(self):
        raise NotImplementedError('Notification subscription base dst called. Must Be implemented.')


class NotificationSubscriptionMailConfig(NotificationSubscriptionConfigBase):
    __tablename__ = 'notification_subscription_mail_config'
    id = Column(Integer, ForeignKey('notification_subscription_config_base.id'), primary_key=True)
    email = Column(String(50), nullable=True)
    user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=True)
    user_notified = relationship(
        'User',
        backref=backref('notification_subscription_mail_config', cascade="all, delete-orphan")
    )

    __mapper_args__ = {
        'polymorphic_identity': NOTIFICATION_METHODS[0]
    }


class NotificationSubscriptionWebHookConfig(NotificationSubscriptionConfigBase):
    __tablename__ = 'notification_subscription_webhook_config'
    id = Column(Integer, ForeignKey('notification_subscription_config_base.id'), primary_key=True)
    url = Column(String(50), nullable=False)
    __mapper_args__ = {
        'polymorphic_identity': NOTIFICATION_METHODS[1]
    }


class NotificationSubscriptionWebSocketConfig(NotificationSubscriptionConfigBase):
    __tablename__ = 'notification_subscription_websocket_config'
    id = Column(Integer, ForeignKey('notification_subscription_config_base.id'), primary_key=True)
    user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=True)
    user_notified = relationship(
        'User',
        backref=backref('notification_subscription_websocket_config', cascade="all, delete-orphan")
    )
    __mapper_args__ = {
        'polymorphic_identity': NOTIFICATION_METHODS[2]
    }


class NotificationEvent(db.Model):
    __tablename__ = 'notification_event'
    id = Column(Integer, primary_key=True)
    event_type_id = Column(Integer, ForeignKey('event_type.id'), index=True, nullable=False)
    event_type = relationship(
        'EventType',
        backref=backref('notification_event_type', cascade="all, delete-orphan")
    )
    object_id = Column(Integer, nullable=False)
    object_type_id = Column(Integer, ForeignKey('object_type.id'), index=True, nullable=False)
    object_type = relationship(
        'ObjectType',
        backref=backref('notification_event_object_type', cascade="all, delete-orphan")
    )

    notification_data = Column(JSONType, nullable=False)
    create_date = Column(DateTime, default=datetime.utcnow)

    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=True)
    workspace = relationship(
        'Workspace',
        backref=backref('notification_event_workspace', cascade="all, delete-orphan"),
    )

    @property
    def parent(self):
        return


class NotificationBase(db.Model):
    __tablename__ = 'notification_base'
    id = Column(Integer, primary_key=True)
    notification_event_id = Column(Integer, ForeignKey('notification_event.id', ondelete="CASCADE"), index=True, nullable=False)
    notification_event = relationship(
        'NotificationEvent',
        backref=backref('notifications', cascade="all, delete-orphan"),
    )
    notification_subscription_config_id = Column(Integer, ForeignKey('notification_subscription_config_base.id'),
                                                 index=True, nullable=False)
    notification_subscription_config = relationship(
        'NotificationSubscriptionConfigBase',
        backref=backref('notifications', cascade="all, delete-orphan"),
    )

    type = Column(String(24))

    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }


# TBI
class MailNotification(NotificationBase):
    __tablename__ = 'mail_notification'

    id = Column(Integer, ForeignKey('notification_base.id'), primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': NOTIFICATION_METHODS[0]
    }


# TBI
class WebHookNotification(NotificationBase):
    __tablename__ = 'webhook_notification'

    id = Column(Integer, ForeignKey('notification_base.id'), primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': NOTIFICATION_METHODS[1]
    }


class WebsocketNotification(NotificationBase):
    __tablename__ = 'websocket_notification'

    id = Column(Integer, ForeignKey('notification_base.id', ondelete='CASCADE'), primary_key=True)
    user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True)
    user_notified = relationship(
        'User',
        backref=backref('notifications', cascade="all, delete-orphan")
    )

    mark_read = Column(Boolean, default=False, index=True)

    __mapper_args__ = {
        'polymorphic_identity': NOTIFICATION_METHODS[2]
    }


class Notification(db.Model):
    __tablename__ = 'notification'
    id = Column(Integer, primary_key=True)
    user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=False)
    user_notified = relationship(
        'User',
        backref=backref('notification', cascade="all, delete-orphan"),
        # primaryjoin="User.id == Notification.user_notified_id"
    )

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)
    notification_text = Column(Text, nullable=False)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('notification', cascade="all, delete-orphan"),
        # primaryjoin="Notification.id == Notification.workspace_id"
    )

    mark_read = Column(Boolean, default=False, index=True)
    create_date = Column(DateTime, default=datetime.utcnow)

    @property
    def parent(self):
        return


def rule_default_name(context):
    model = context.get_current_parameters()['model']
    create_date = context.get_current_parameters()['create_date']
    return f'Job for model {model} @ {create_date.isoformat()}'


association_pipelines_and_jobs_table = Table(
    'association_pipelines_and_jobs_table',
    db.Model.metadata,
    Column('pipeline_id', Integer, ForeignKey('pipeline.id')),
    Column('workflow_id', Integer, ForeignKey('workflow.id'))
)


class Pipeline(Metadata):
    __tablename__ = "pipeline"
    id = Column(Integer, primary_key=True)
    name = Column(String, default=f"Pipeline-{datetime.now()}", unique=True, nullable=False)
    description = Column(String, default="", nullable=False)
    jobs_order = Column(String, default="")
    jobs = relationship(
        'Workflow',
        secondary=association_pipelines_and_jobs_table,
        back_populates="pipelines"
    )
    # N to 1
    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="SET NULL"), index=True, nullable=True)
    workspace = relationship('Workspace', backref=backref('pipelines'))

    enabled = Column(Boolean, nullable=False, default=False)
    running = Column(Boolean, nullable=False, default=False)

    @property
    def parent(self):
        return


class Workflow(Metadata):
    VALID_MODELS = ("vulnerability", "vulnerability_web", "host", "service")

    __tablename__ = 'workflow'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True, default=rule_default_name)
    description = Column(String, nullable=False, default='')
    model = Column(Enum(*VALID_MODELS, name='valid_workflow_models'), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    # run_on_updates = Column(Boolean, nullable=False, default=True)
    # actions_order = Column(String, nullable=False, default='')
    # N to N
    # actions = relationship(
    #     'Action',
    #     secondary=association_workflows_and_actions_table,
    #     back_populates="workflows"
    # )
    # N to N
    pipelines = relationship(
        'Pipeline',
        secondary=association_pipelines_and_jobs_table,
        back_populates="jobs"
    )
    # # N to 1
    # workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    # workspace = relationship('Workspace', backref=backref('workflows', cascade="all, delete-orphan"))
    # 1 to N
    conditions = relationship('Condition', back_populates='workflow', cascade="all, delete-orphan")
    # 1 to N
    actions = relationship('Action', back_populates='workflow', cascade="all, delete-orphan")
    # 1 to N
    executions = relationship('WorkflowExecution', back_populates='workflow', cascade="all, delete-orphan")

    # __table_args__ = (
    #     UniqueConstraint('name', 'workspace_id', name='uix_name_workspaceid'),
    # )

    @property
    def parent(self):
        return

    @property
    def root_condition(self):
        for condition in self.conditions:
            if condition.is_root:
                return condition
        return None


class Condition(Metadata):
    TYPES = ['and', 'or', 'xor', 'leaf']

    __tablename__ = 'condition'
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey('condition.id'))
    parent = relationship("Condition", remote_side=[id])
    children = relationship("Condition", lazy="joined", join_depth=2)
    type = Column(Enum(*TYPES, name='condition_types'))
    field = Column(String(50), nullable=True)
    operator = Column(String(50), nullable=True)
    data = Column(String(50), nullable=True)
    is_root = Column(Boolean, nullable=False, default=False)

    # N to 1
    workflow_id = Column(Integer, ForeignKey('workflow.id'), index=True, nullable=False)
    workflow = relationship('Workflow', back_populates="conditions")


class Action(Metadata):
    __tablename__ = 'action'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=True)
    description = Column(String, nullable=False, default='')
    command = Column(String, nullable=False)
    field = Column(String, nullable=True)
    value = Column(String, nullable=True)
    custom_field = Column(Boolean, default=False)
    target = Column(String, nullable=True, default='')

    # N to 1
    workflow_id = Column(Integer, ForeignKey('workflow.id'), index=True, nullable=True)
    workflow = relationship('Workflow', back_populates="actions")


class WorkflowExecution(Metadata):
    __tablename__ = 'workflow_execution'
    id = Column(Integer, primary_key=True)
    successful = Column(Boolean, nullable=False)
    message = Column(String, nullable=False)
    workflow_id = Column(Integer, ForeignKey('workflow.id'), index=True, nullable=False)
    workflow = relationship('Workflow', back_populates='executions')
    object_and_id = Column(String, nullable=False)


class Executor(Metadata):
    __tablename__ = 'executor'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    agent_id = Column(Integer, ForeignKey('agent.id', ondelete='CASCADE'), index=True, nullable=False)
    agent = relationship(
        'Agent',
        backref=backref('executors', cascade="all, delete-orphan"),
    )
    parameters_metadata = Column(JSONType, nullable=False, default={})
    last_run = Column(DateTime)
    # workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    # workspace = relationship('Workspace', backref=backref('executors', cascade="all, delete-orphan"))

    __table_args__ = (
        UniqueConstraint('name', 'agent_id', name='uix_executor_table_agent_id_name'),
    )


agents_schedule_workspace_table = Table(
    "agents_schedule_workspace_table",
    db.Model.metadata,
    Column("workspace_id", Integer, ForeignKey("workspace.id", ondelete="CASCADE")),
    Column("agents_schedule_id", Integer, ForeignKey("agent_schedule.id")),
)


class AgentsSchedule(Metadata):
    __tablename__ = 'agent_schedule'
    id = Column(Integer, primary_key=True)
    description = NonBlankColumn(Text)
    crontab = NonBlankColumn(Text)
    timezone = NonBlankColumn(Text)
    active = Column(Boolean, nullable=False, default=True)
    last_run = Column(DateTime)

    # N workspace <--> N schedules
    workspaces = relationship(
        'Workspace',
        secondary=agents_schedule_workspace_table,
        backref='agent_schedule',
    )
    executor_id = Column(Integer, ForeignKey('executor.id'), index=True, nullable=False)
    executor = relationship(
        'Executor',
        backref=backref('schedules', cascade="all, delete-orphan"),
    )
    ignore_info = Column(Boolean, default=False)
    resolve_hostname = Column(Boolean, default=True)
    vuln_tag = Column(String, default="")
    service_tag = Column(String, default="")
    host_tag = Column(String, default="")
    parameters = Column(JSONType, nullable=False, default={})

    @property
    def next_run(self):
        return croniter(
            self.crontab,
            datetime.now(tz=dateutil.tz.gettz(self.timezone)),
            ret_type=datetime
        ).get_next(datetime)

    @property
    def parent(self):
        return self.executor.agent


class Agent(Metadata):
    __tablename__ = 'agent'
    id = Column(Integer, primary_key=True)
    token = Column(Text, unique=True, nullable=False, default=lambda: "".
                   join([SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(64)]))
    name = NonBlankColumn(Text)
    active = Column(Boolean, default=True)
    sid = Column(Text)  # socketio sid

    @property
    def parent(self):
        return

    @property
    def is_online(self):
        return self.sid is not None

    @property
    def is_offline(self):
        return self.sid is None

    @property
    def status(self):
        if self.active:
            if self.is_online:
                return 'online'
            else:
                return 'offline'
        else:
            return 'paused'

    @property
    def last_run(self):
        execs = db.session.query(Executor).filter_by(agent_id=self.id)
        if execs:
            _last_run = None
            for exe in execs:
                if _last_run is None or (exe.last_run is not None and _last_run - exe.last_run <= timedelta()):
                    _last_run = exe.last_run
            return _last_run
        return None

    def __repr__(self):
        return f"Agent {self.name}"


class AgentExecution(Metadata):
    __tablename__ = 'agent_execution'
    id = Column(Integer, primary_key=True)
    running = Column(Boolean, nullable=True)
    successful = Column(Boolean, nullable=True)
    message = Column(String, nullable=True)
    executor_id = Column(Integer, ForeignKey('executor.id'), index=True, nullable=False)
    executor = relationship('Executor', foreign_keys=[executor_id],
                            backref=backref('executions', cascade="all, delete-orphan"))

    # 1 workspace <--> N agent_executions
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('agent_executions', cascade="all, delete-orphan")
    )
    parameters_data = Column(JSONType, nullable=False)
    command_id = Column(Integer, ForeignKey('command.id', ondelete='SET NULL'), index=True)
    command = relationship(
        'Command',
        foreign_keys=[command_id],
        backref=backref('agent_execution_id', cascade="all, delete-orphan")
    )

    @property
    def parent(self):
        return

    def notification_message(self, _event, user=None):
        if self.command.end_date:
            return f"{self.executor.agent.name} finished"
        elif self.running:
            return f"{self.executor.agent.name} running"


class CloudAgent(Metadata):
    __tablename__ = "cloud_agent"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True)
    access_token = Column(Text, unique=True)
    params = Column(JSONType)

    @property
    def last_run(self):
        execs = db.session.query(CloudAgentExecution).filter_by(cloud_agent_id=self.id)
        if execs:
            _last_run = None
            for exe in execs:
                if _last_run is None or (exe.last_run is not None and _last_run - exe.last_run <= timedelta()):
                    _last_run = exe.last_run
            return _last_run
        return None

    @property
    def parent(self):
        return


class CloudAgentExecution(Metadata):
    __tablename__ = 'cloud_agent_execution'
    id = Column(Integer, primary_key=True)
    running = Column(Boolean, nullable=True)
    successful = Column(Boolean, nullable=True)
    message = Column(String, nullable=True)

    cloud_agent_id = Column(Integer, ForeignKey('cloud_agent.id', ondelete='CASCADE'), index=True, nullable=False)
    cloud_agent = relationship(
        'CloudAgent',
        backref=backref('cloud_agent_executions', cascade="all, delete-orphan"),
    )

    # 1 workspace <--> N cloud_agent_executions
    # 1 to N (the FK is placed in the child) and bidirectional (backref)
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('cloud_agent_executions', cascade="all, delete-orphan")
    )
    parameters_data = Column(JSONType, nullable=False)
    command_id = Column(Integer, ForeignKey('command.id', ondelete='SET NULL'), index=True)
    command = relationship(
        'Command',
        foreign_keys=[command_id],
        backref=backref('cloud_agent_execution_id', cascade="all, delete-orphan")
    )
    last_run = Column(DateTime)

    @property
    def parent(self):
        return


class SearchFilter(Metadata):
    __tablename__ = 'search_filter'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    json_query = Column(String, nullable=False)  # meant to store json but just readonly
    user_query = Column(String, nullable=False)


class Configuration(Metadata):
    __tablename__ = "configuration"
    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(JSONType, nullable=False)


class AnalyticsConfig:
    VULNS_PER_HOST = 'vulnerabilities_per_host'
    VULNS_PER_STATUS = 'vulnerabilities_per_status'
    VULNS_PER_SEVERITY = 'vulnerabilities_per_severity'
    TOP_TEN_MOST_AFFECTED_HOSTS = 'top_ten_most_affected_hosts'
    TOP_TEN_MOST_REPEATED_VULNS = 'top_ten_most_repeated_vulns'
    MONTHLY_EVOLUTION_BY_STATUS = 'monthly_evolution_by_status'
    MONTHLY_EVOLUTION_BY_SEVERITY = 'monthly_evolution_by_severity'
    VULNERABILITIES_BY_RISK_SCORE = 'vulnerabilities_by_risk_score'

    TYPES = [
        VULNS_PER_HOST,
        VULNS_PER_STATUS,
        VULNS_PER_SEVERITY,
        TOP_TEN_MOST_AFFECTED_HOSTS,
        TOP_TEN_MOST_REPEATED_VULNS,
        MONTHLY_EVOLUTION_BY_STATUS,
        MONTHLY_EVOLUTION_BY_SEVERITY,
        VULNERABILITIES_BY_RISK_SCORE
    ]


class Analytics(Metadata):
    __tablename__ = "analytics"

    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    type = Column(Enum(*AnalyticsConfig.TYPES, name='analytics_types'), nullable=False)
    filters = Column(JSONType, nullable=False)
    data = Column(JSONType, nullable=False)
    show_data_table = Column(Boolean, default=False)


class BaseNotification(Metadata):
    __tablename__ = "base_notification"

    id = Column(Integer, primary_key=True)
    data = Column(JSONType, nullable=False)
    processed = Column(Boolean, default=False)
    verbose = Column(Boolean, default=False)

    def __repr__(self):
        return f"Notification ID:{self.id}, type:{self.data.get('type')}, subtype:{self.data.get('subtype')}"


class UserNotification(Metadata):
    __tablename__ = "user_notification"

    id = Column(Integer, primary_key=True)
    message = Column(Text, nullable=False)
    extra_data = Column(JSONType, nullable=True)
    type = Column(String, nullable=False)
    subtype = Column(String, nullable=False)
    read = Column(Boolean, default=False)
    triggered_by = Column(JSONType)
    user_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=False)
    user = relationship('User',
                        backref=backref('user_notifications', cascade="all, delete-orphan"),
                        foreign_keys=[user_id])
    links_to = Column(JSONType, nullable=True)
    event_date = Column(DateTime, default=datetime.utcnow(), nullable=False)

    def mark_as_read(self):
        self.read = True

    def __repr__(self):
        return f"{self.message}"


class UserNotificationSettings(Metadata):
    __tablename__ = 'user_notification_settings'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('faraday_user.id'))
    user = relationship('User',
                        backref=backref('notification_settings', uselist=False, cascade="all, delete-orphan"),
                        foreign_keys=[user_id])

    paused = Column(Boolean, default=False)
    slack_id = Column(String, nullable=True, default=None)
    no_self_notify = Column(Boolean, default=False)

    agents_enabled = Column(Boolean, default=True)
    agents_app = Column(Boolean, default=True)
    agents_email = Column(Boolean, default=False)
    agents_slack = Column(Boolean, default=False)

    cli_enabled = Column(Boolean, default=True)
    cli_app = Column(Boolean, default=True)
    cli_email = Column(Boolean, default=False)
    cli_slack = Column(Boolean, default=False)

    comments_enabled = Column(Boolean, default=True)
    comments_app = Column(Boolean, default=True)
    comments_email = Column(Boolean, default=False)
    comments_slack = Column(Boolean, default=False)

    hosts_enabled = Column(Boolean, default=True)
    hosts_app = Column(Boolean, default=True)
    hosts_email = Column(Boolean, default=False)
    hosts_slack = Column(Boolean, default=False)

    users_enabled = Column(Boolean, default=True)
    users_app = Column(Boolean, default=True)
    users_email = Column(Boolean, default=False)
    users_slack = Column(Boolean, default=False)

    reports_enabled = Column(Boolean, default=True)
    reports_app = Column(Boolean, default=True)
    reports_email = Column(Boolean, default=False)
    reports_slack = Column(Boolean, default=False)

    vulnerabilities_enabled = Column(Boolean, default=True)
    vulnerabilities_app = Column(Boolean, default=True)
    vulnerabilities_email = Column(Boolean, default=False)
    vulnerabilities_slack = Column(Boolean, default=False)

    workspaces_enabled = Column(Boolean, default=True)
    workspaces_app = Column(Boolean, default=True)
    workspaces_email = Column(Boolean, default=False)
    workspaces_slack = Column(Boolean, default=False)

    pipelines_enabled = Column(Boolean, default=True)
    pipelines_app = Column(Boolean, default=True)
    pipelines_email = Column(Boolean, default=False)
    pipelines_slack = Column(Boolean, default=False)

    executive_reports_enabled = Column(Boolean, default=True)
    executive_reports_app = Column(Boolean, default=True)
    executive_reports_email = Column(Boolean, default=False)
    executive_reports_slack = Column(Boolean, default=False)

    planner_enabled = Column(Boolean, default=True)
    planner_app = Column(Boolean, default=True)
    planner_email = Column(Boolean, default=False)
    planner_slack = Column(Boolean, default=False)

    integrations_enabled = Column(Boolean, default=True)
    integrations_app = Column(Boolean, default=True)
    integrations_email = Column(Boolean, default=False)
    integrations_slack = Column(Boolean, default=False)

    other_enabled = Column(Boolean, default=True)
    other_app = Column(Boolean, default=True)
    other_email = Column(Boolean, default=False)
    other_slack = Column(Boolean, default=False)

    adv_high_crit_vuln_enabled = Column(Boolean, default=False)
    adv_high_crit_vuln_app = Column(Boolean, default=False)
    adv_high_crit_vuln_email = Column(Boolean, default=False)
    adv_high_crit_vuln_slack = Column(Boolean, default=False)
    adv_high_crit_vuln = Column(Boolean, default=False)

    adv_risk_score_threshold_enabled = Column(Boolean, default=False)
    adv_risk_score_threshold_app = Column(Boolean, default=False)
    adv_risk_score_threshold_email = Column(Boolean, default=False)
    adv_risk_score_threshold_slack = Column(Boolean, default=False)
    adv_risk_score_threshold = Column(Integer, default=0)

    adv_vuln_open_days_critical_enabled = Column(Boolean, default=False)
    adv_vuln_open_days_critical_app = Column(Boolean, default=False)
    adv_vuln_open_days_critical_email = Column(Boolean, default=False)
    adv_vuln_open_days_critical_slack = Column(Boolean, default=False)
    adv_vuln_open_days_critical = Column(Integer, default=0)

    adv_vuln_open_days_high_enabled = Column(Boolean, default=False)
    adv_vuln_open_days_high_app = Column(Boolean, default=False)
    adv_vuln_open_days_high_email = Column(Boolean, default=False)
    adv_vuln_open_days_high_slack = Column(Boolean, default=False)
    adv_vuln_open_days_high = Column(Integer, default=0)

    adv_vuln_open_days_medium_enabled = Column(Boolean, default=False)
    adv_vuln_open_days_medium_app = Column(Boolean, default=False)
    adv_vuln_open_days_medium_email = Column(Boolean, default=False)
    adv_vuln_open_days_medium_slack = Column(Boolean, default=False)
    adv_vuln_open_days_medium = Column(Integer, default=0)

    adv_vuln_open_days_low_enabled = Column(Boolean, default=False)
    adv_vuln_open_days_low_app = Column(Boolean, default=False)
    adv_vuln_open_days_low_email = Column(Boolean, default=False)
    adv_vuln_open_days_low_slack = Column(Boolean, default=False)
    adv_vuln_open_days_low = Column(Integer, default=0)


class EmailNotification(db.Model):
    id = Column(Integer, primary_key=True)
    user_email = Column(String, nullable=False)
    message = Column(String, nullable=False)
    processed = Column(Boolean, default=False)


class SlackNotification(db.Model):
    id = Column(Integer, primary_key=True)
    slack_id = Column(String, nullable=False)
    message = Column(String, nullable=False)
    processed = Column(Boolean, default=False)


# Indexes to speed up queries
Index("idx_vulnerability_severity_hostid_serviceid",
      VulnerabilityGeneric.__table__.c.severity,
      VulnerabilityGeneric.__table__.c.host_id,
      VulnerabilityGeneric.__table__.c.service_id)

Index("ix_vulnerability_severity_serviceid",
      VulnerabilityGeneric.__table__.c.severity,
      VulnerabilityGeneric.__table__.c.service_id)

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
import faraday.server.events  # noqa F401
