# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import json

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    Float,
    Text,
    UniqueConstraint
)
from sqlalchemy import create_engine
from sqlalchemy.orm import relationship, scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from server.utils.database import get_or_create


SCHEMA_VERSION = 'W.2.6.0'

Base = declarative_base()
engine = create_engine('sqlite:////home/leonardo/faraday.sqlite', echo=False)
session = scoped_session(sessionmaker(autocommit=False,
                                           autoflush=False,
                                           bind=engine))



class EntityNotFound(Exception):
    def __init__(self, entity_id):
        super(EntityNotFound, self).__init__("Entity (%s) wasn't found" % entity_id)


class FaradayEntity(object):
    # Document Types: [u'Service', u'Communication', u'Vulnerability', u'CommandRunInformation', u'Reports', u'Host', u'Workspace', u'Interface']
    @classmethod
    def parse(cls, document):
        """Get an instance of a DAO object given a document"""
        entity_cls = cls.get_entity_class_from_doc(document)
        if entity_cls is not None:
            entity = entity_cls.update_from_document(document)
            metadata = EntityMetadata.update_from_document(document)
            entity.entity_metadata = metadata
            return entity
        return None

    @classmethod
    def get_entity_class_from_doc(cls, document):
        return cls.get_entity_class_from_type(document.get('type', None))

    @classmethod
    def get_entity_class_from_type(cls, doc_type):
        for entity_cls in cls.__subclasses__():
            if isinstance(entity_cls.DOC_TYPE, basestring):
                if entity_cls.DOC_TYPE == doc_type:
                    return entity_cls
            else:
                if doc_type in entity_cls.DOC_TYPE:
                    return entity_cls
        return None

    @classmethod
    def update_from_document(self, document):
        raise Exception('MUST IMPLEMENT')

    def add_relationships_from_dict(self, entities):
        pass

    def add_relationships_from_db(self, session):
        pass


class DatabaseMetadata(Base):
    __tablename__ = 'db_metadata'
    id = Column(Integer, primary_key=True)
    option = Column(String(250), nullable=False)
    value = Column(String(250), nullable=False)


class EntityMetadata(Base):
    # Table schema
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

    @classmethod
    def update_from_document(cls, document):
        entity, created = get_or_create(session, cls, couchdb_id=document.get('_id'))
        metadata = document.get('metadata', dict())
        entity.update_time = metadata.get('update_time', None)
        entity.update_user = metadata.get('update_user', None)
        entity.update_action = metadata.get('update_action', None)
        entity.creator = metadata.get('creator', None)
        entity.owner = metadata.get('owner', None)
        entity.create_time = metadata.get('create_time', None)
        entity.update_controller_action = metadata.get('update_controller_action', None)
        entity.revision = document.get('_rev')
        entity.document_type = document.get('type')
        entity.command_id = metadata.get('command_id', None)

        if entity.create_time is not None:
            entity.create_time = entity.__truncate_to_epoch_in_seconds(entity.create_time)

        return entity

    def __truncate_to_epoch_in_seconds(self, timestamp):
        """ In a not so elegant fashion, identifies and truncate
        epoch timestamps expressed in milliseconds to seconds"""
        limit = 32503680000  # 01 Jan 3000 00:00:00 GMT
        if timestamp > limit:
            return timestamp / 1000
        else:
            return timestamp


class Host(FaradayEntity, Base):
    DOC_TYPE = 'Host'

    # Table schema
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

    @classmethod
    def update_from_document(cls, document):
        # Ticket #3387: if the 'os' field is None, we default to 'unknown'
        host = cls()
        if not document.get('os'):
            document['os'] = 'unknown'

        default_gateway = document.get('default_gateway', None)

        host.name = document.get('name')
        host.description = document.get('description')
        host.os = document.get('os')
        host.default_gateway_ip = default_gateway and default_gateway[0] or ''
        host.default_gateway_mac = default_gateway and default_gateway[1] or ''
        host.owned = document.get('owned', False)
        return host


class Interface(FaradayEntity, Base):
    DOC_TYPE = 'Interface'

    # Table schema
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

    @classmethod
    def update_from_document(cls, document):
        interface = cls()
        interface.name = document.get('name')
        interface.description = document.get('description')
        interface.mac = document.get('mac')
        interface.owned = document.get('owned', False)
        interface.hostnames = u','.join(document.get('hostnames'))
        interface.network_segment = document.get('network_segment')
        interface.ipv4_address = document.get('ipv4').get('address')
        interface.ipv4_gateway = document.get('ipv4').get('gateway')
        interface.ipv4_dns = u','.join(document.get('ipv4').get('DNS'))
        interface.ipv4_mask = document.get('ipv4').get('mask')
        interface.ipv6_address = document.get('ipv6').get('address')
        interface.ipv6_gateway = document.get('ipv6').get('gateway')
        interface.ipv6_dns = u','.join(document.get('ipv6').get('DNS'))
        interface.ipv6_prefix = str(document.get('ipv6').get('prefix'))
        interface.ports_filtered = document.get('ports', {}).get('filtered')
        interface.ports_opened = document.get('ports', {}).get('opened')
        interface.ports_closed = document.get('ports', {}).get('closed')
        return interface

    def add_relationships_from_dict(self, entities):
        host_id = '.'.join(self.entity_metadata.couchdb_id.split('.')[:-1])
        if host_id not in entities:
            raise EntityNotFound(host_id)
        self.host = entities[host_id]

    def add_relationships_from_db(self, session):
        host_id = '.'.join(self.entity_metadata.couchdb_id.split('.')[:-1])
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        self.host = query.one()


class Service(FaradayEntity, Base):
    DOC_TYPE = 'Service'

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

    @classmethod
    def update_from_document(cls, document):
        service = cls()
        service.name = document.get('name')
        service.description = document.get('description')
        service.owned = document.get('owned', False)
        service.protocol = document.get('protocol')
        service.status = document.get('status')
        service.version = document.get('version')

        # We found workspaces where ports are defined as an integer
        if isinstance(document.get('ports', None), (int, long)):
            service.ports = str(document.get('ports'))
        else:
            service.ports = u','.join(map(str, document.get('ports')))
        return service

    def add_relationships_from_dict(self, entities):
        couchdb_id = self.entity_metadata.couchdb_id

        host_id = couchdb_id.split('.')[0]
        if host_id not in entities:
            raise EntityNotFound(host_id)
        self.host = entities[host_id]

        interface_id = '.'.join(couchdb_id.split('.')[:-1])
        if interface_id not in entities:
            raise EntityNotFound(interface_id)
        self.interface = entities[interface_id]

    def add_relationships_from_db(self, session):
        couchdb_id = self.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        self.host = query.one()

        interface_id = '.'.join(couchdb_id.split('.')[:-1])
        query = session.query(Interface).join(EntityMetadata).filter(EntityMetadata.couchdb_id == interface_id)
        self.interface = query.one()


class Vulnerability(FaradayEntity, Base):
    DOC_TYPE = ['Vulnerability', 'VulnerabilityWeb']

    # Table schema
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

    @classmethod
    def update_from_document(cls, document):
        vulnerability = cls()
        vulnerability.name = document.get('name')
        vulnerability.description = document.get('desc')
        vulnerability.confirmed = document.get('confirmed')
        vulnerability.vuln_type = document.get('type')
        vulnerability.data = document.get('data')
        vulnerability.easeofresolution = document.get('easeofresolution')
        vulnerability.refs = json.dumps(document.get('refs', []))
        vulnerability.resolution = document.get('resolution')
        vulnerability.severity = document.get('severity')
        vulnerability.owned = document.get('owned', False)
        vulnerability.attachments = json.dumps(document.get('_attachments', {}))
        vulnerability.policyviolations = json.dumps(document.get('policyviolations', []))
        vulnerability.impact_accountability = document.get('impact', {}).get('accountability')
        vulnerability.impact_availability = document.get('impact', {}).get('availability')
        vulnerability.impact_confidentiality = document.get('impact', {}).get('confidentiality')
        vulnerability.impact_integrity = document.get('impact', {}).get('integrity')
        vulnerability.method = document.get('method')
        vulnerability.path = document.get('path')
        vulnerability.pname = document.get('pname')
        vulnerability.query = document.get('query')
        vulnerability.request = document.get('request')
        vulnerability.response = document.get('response')
        vulnerability.website = document.get('website')
        vulnerability.status = document.get('status', 'opened')

        params = document.get('params', u'')
        if isinstance(params, (list, tuple)):
            vulnerability.params = (u' '.join(params)).strip()
        else:
            vulnerability.params = params if params is not None else u''

        return vulnerability

    def add_relationships_from_dict(self, entities):
        couchdb_id = self.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        if host_id not in entities:
            raise EntityNotFound(host_id)
        self.host = entities[host_id]

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            if parent_id not in entities:
                raise EntityNotFound(parent_id)
            self.service = entities[parent_id]

    def add_relationships_from_db(self, session):
        couchdb_id = self.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        self.host = query.one()

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            query = session.query(Service).join(EntityMetadata).filter(EntityMetadata.couchdb_id == parent_id)
            self.service = query.one()


class Note(FaradayEntity, Base):
    DOC_TYPE = 'Note'

    # Table schema
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

    @classmethod
    def update_from_document(cls, document):
        note = cls*()
        note.name = document.get('name')
        note.text = document.get('text', None)
        note.description = document.get('description', None)
        note.owned = document.get('owned', False)
        return note


class Credential(FaradayEntity, Base):
    DOC_TYPE = 'Cred'

    # Table schema
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

    @classmethod
    def update_from_document(cls, document):
        credential = cls()
        credential.username = document.get('username')
        credential.password = document.get('password', '')
        credential.owned = document.get('owned', False)
        credential.description = document.get('description', '')
        credential.name = document.get('name', '')
        return credential

    def add_relationships_from_dict(self, entities):
        couchdb_id = self.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        if host_id not in entities:
            raise EntityNotFound(host_id)
        self.host = entities[host_id]

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            if parent_id not in entities:
                raise EntityNotFound(parent_id)
            self.service = entities[parent_id]

    def add_relationships_from_db(self, session):
        couchdb_id = self.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        self.host = query.one()

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            query = session.query(Service).join(EntityMetadata).filter(EntityMetadata.couchdb_id == parent_id)
            self.service = query.one()


class Command(FaradayEntity, Base):
    DOC_TYPE = 'CommandRunInformation'

    # Table schema
    __tablename__ = 'command'
    id = Column(Integer, primary_key=True)
    command = Column(String(250), nullable=True)
    duration = Column(Float, nullable=True)
    itime = Column(Float, nullable=True)
    ip = Column(String(250), nullable=True)
    hostname = Column(String(250), nullable=True)
    params = Column(String(250), nullable=True)
    user = Column(String(250), nullable=True)
    workspace = Column(String(250), nullable=True)
    workspace = relationship('Workspace')
    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True)

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    @classmethod
    def update_from_document(cls, document):
        command, instance = get_or_create(session, cls, command=document.get('command', None))
        command.command = document.get('command', None)
        command.duration = document.get('duration', None)
        command.itime = document.get('itime', None)
        command.ip = document.get('ip', None)
        command.hostname = document.get('hostname', None)
        command.params = document.get('params', None)
        command.user = document.get('user', None)

        workspace_name = document.get('workspace', None)
        if workspace_name:
            workspace, instance = get_or_create(session, Workspace, name=document.get('workspace', None))
            command.workspace = workspace

        return command


class Workspace(FaradayEntity, Base):
    DOC_TYPE = 'Workspace'

    __tablename__ = 'workspace'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=True)

    @classmethod
    def update_from_document(cls, document):
        workspace = cls()
        workspace.name = document.get('name', None)
        return workspace
