# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import json

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Float, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base


SCHEMA_VERSION = 'W.0.3'

Base = declarative_base()

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
            entity = entity_cls(document)
            metadata = EntityMetadata(document)
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

    def __init__(self, document):
        self.update_from_document(document)

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
    id = Column(Integer, primary_key=True)
    update_time = Column(Float, nullable=True)
    update_user = Column(String(250), nullable=True)
    update_action = Column(Integer, nullable=True)
    create_time = Column(Float, nullable=True)
    update_controller_action = Column(String(250), nullable=True)
    creator = Column(String(250), nullable=True)
    owner = Column(String(250), nullable=True)

    couchdb_id = Column(String(250))
    revision = Column(String(250))
    document_type = Column(String(250))

    def __init__(self, document):
        self.update_from_document(document)

    def update_from_document(self, document):
        metadata = document.get('metadata', dict())
        self.update_time=metadata.get('update_time', None)
        self.update_user=metadata.get('update_user', None)
        self.update_action=metadata.get('update_action', None)
        self.creator=metadata.get('creator', None)
        self.owner=metadata.get('owner', None)
        self.create_time=metadata.get('create_time', None)
        self.update_controller_action=metadata.get('update_controller_action', None)
        self.couchdb_id=document.get('_id')
        self.revision=document.get('_rev')
        self.document_type=document.get('type')


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

    def update_from_document(self, document):
        default_gateway = self.__get_default_gateway(document)

        self.name=document.get('name')
        self.description=document.get('description')
        self.os=document.get('os')
        self.default_gateway_ip=default_gateway[0]
        self.default_gateway_mac=default_gateway[1]
        self.owned=document.get('owned', False)

    def __get_default_gateway(self, document):
        default_gateway = document.get('default_gateway', None)
        if default_gateway:
            return default_gateway
        else:
            return u'', u''


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

    services = relationship('Service')

    def update_from_document(self, document):
        self.name=document.get('name')
        self.description=document.get('description')
        self.mac=document.get('mac')
        self.owned=document.get('owned', False)
        self.hostnames=u','.join(document.get('hostnames'))
        self.network_segment=document.get('network_segment')
        self.ipv4_address=document.get('ipv4').get('address')
        self.ipv4_gateway=document.get('ipv4').get('gateway')
        self.ipv4_dns=u','.join(document.get('ipv4').get('DNS'))
        self.ipv4_mask=document.get('ipv4').get('mask')
        self.ipv6_address=document.get('ipv6').get('address')
        self.ipv6_gateway=document.get('ipv6').get('gateway')
        self.ipv6_dns=u','.join(document.get('ipv6').get('DNS'))
        self.ipv6_prefix=str(document.get('ipv6').get('prefix'))
        self.ports_filtered=document.get('ports').get('filtered')
        self.ports_opened=document.get('ports').get('opened')
        self.ports_closed=document.get('ports').get('closed')

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

    def update_from_document(self, document):
        self.name=document.get('name')
        self.description=document.get('description')
        self.owned=document.get('owned', False)
        self.protocol=document.get('protocol')
        self.status=document.get('status')
        self.version=document.get('version')

        # We found workspaces where ports are defined as an integer
        if isinstance(document.get('ports', None), (int, long)):
            self.ports = str(document.get('ports'))
        else:
            self.ports = u','.join(map(str, document.get('ports')))

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

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    host_id = Column(Integer, ForeignKey(Host.id), index=True)
    host = relationship('Host', back_populates='vulnerabilities')

    service_id = Column(Integer, ForeignKey(Service.id), index=True)
    service = relationship('Service', back_populates='vulnerabilities')

    def update_from_document(self, document):
        self.name = document.get('name')
        self.description=document.get('desc')
        self.confirmed=document.get('confirmed')
        self.vuln_type=document.get('type')
        self.data=document.get('data')
        self.easeofresolution=document.get('easeofresolution')
        self.refs=json.dumps(document.get('refs', []))
        self.resolution=document.get('resolution')
        self.severity=document.get('severity')
        self.owned=document.get('owned', False)
        self.attachments = json.dumps(document.get('_attachments', {}))
        self.impact_accountability=document.get('impact', {}).get('accountability')
        self.impact_availability=document.get('impact', {}).get('availability')
        self.impact_confidentiality=document.get('impact', {}).get('confidentiality')
        self.impact_integrity=document.get('impact', {}).get('integrity')
        self.method=document.get('method')
        self.path=document.get('path')
        self.pname=document.get('pname')
        self.query=document.get('query')
        self.request=document.get('request')
        self.response=document.get('response')
        self.website=document.get('website')

        params = document.get('params', u'')
        if isinstance(params, (list, tuple)):
            self.params = (u' '.join(params)).strip()
        else:
            self.params = params if params is not None else u''

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

    entity_metadata = relationship(EntityMetadata, uselist=False, cascade="all, delete-orphan", single_parent=True)
    entity_metadata_id = Column(Integer, ForeignKey(EntityMetadata.id), index=True)

    def update_from_document(self, document):
        self.name=document.get('name')
        self.text=document.get('text', None)
        self.description=document.get('description', None)

