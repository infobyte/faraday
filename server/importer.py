# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import sys
import json

import server.app
import server.utils.logger
import server.couchdb
import server.database
import server.models
from server.utils.database import get_or_create
from server.models import (
    db,
    EntityMetadata,
    Host,
    Interface,
    Service,
    Note,
    Command,
    Workspace,
    Vulnerability
)
from restkit.errors import RequestError, Unauthorized

from tqdm import tqdm

logger = server.utils.logger.get_logger(__name__)
session = db.session


class EntityNotFound(Exception):
    def __init__(self, entity_id):
        super(EntityNotFound, self).__init__("Entity (%s) wasn't found" % entity_id)


class EntityMetadataImporter(object):

    @classmethod
    def update_from_document(cls, document):
        entity, created = get_or_create(session, EntityMetadata, couchdb_id=document.get('_id'))
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
            entity.create_time = cls.__truncate_to_epoch_in_seconds(entity.create_time)

        return entity

    @classmethod
    def __truncate_to_epoch_in_seconds(self, timestamp):
        """ In a not so elegant fashion, identifies and truncate
        epoch timestamps expressed in milliseconds to seconds"""
        limit = 32503680000  # 01 Jan 3000 00:00:00 GMT
        if timestamp > limit:
            return timestamp / 1000
        else:
            return timestamp


class HostImporter(object):
    DOC_TYPE = 'Host'

    @classmethod
    def update_from_document(cls, document):
        # Ticket #3387: if the 'os' field is None, we default to 'unknown'
        host = Host()
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

    def add_relationships_from_dict(self, host, entities):
        assert len(filter(lambda entity: isinstance(entity, Workspace), entities)) <= 1
        for couch_id, entity in entities.items():
            if isinstance(entity, Workspace):
                host.workspace = entity


    def __get_default_gateway(self, document):
        default_gateway = document.get('default_gateway', None)
        if default_gateway:
            return default_gateway
        else:
            return u'', u''


class InterfaceImporter(object):
    DOC_TYPE = 'Interface'

    @classmethod
    def update_from_document(cls, document):
        interface = Interface()
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

    def add_relationships_from_dict(self, entity, entities):
        host_id = '.'.join(entity.entity_metadata.couchdb_id.split('.')[:-1])
        if host_id not in entities:
            raise EntityNotFound(host_id)
        entity.host = entities[host_id]

    def add_relationships_from_db(self, entity, session):
        host_id = '.'.join(entity.entity_metadata.couchdb_id.split('.')[:-1])
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        entity.host = query.one()


class ServiceImporter(object):
    DOC_TYPE = 'Service'

    @classmethod
    def update_from_document(cls, document):
        service = Service()
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

    def add_relationships_from_dict(self, entity, entities):
        couchdb_id = entity.entity_metadata.couchdb_id

        host_id = couchdb_id.split('.')[0]
        if host_id not in entities:
            raise EntityNotFound(host_id)
        entity.host = entities[host_id]

        interface_id = '.'.join(couchdb_id.split('.')[:-1])
        if interface_id not in entities:
            raise EntityNotFound(interface_id)
        entity.interface = entities[interface_id]

    def add_relationships_from_db(self, entity, session):
        couchdb_id = entity.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        entity.host = query.one()

        interface_id = '.'.join(couchdb_id.split('.')[:-1])
        query = session.query(Interface).join(EntityMetadata).filter(EntityMetadata.couchdb_id == interface_id)
        entity.interface = query.one()


class VulnerabilityImporter(object):
    DOC_TYPE = ['Vulnerability', 'VulnerabilityWeb']

    @classmethod
    def update_from_document(cls, document):
        vulnerability = Vulnerability()
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

    def add_relationships_from_dict(self, entity, entities):
        couchdb_id = entity.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        if host_id not in entities:
            raise EntityNotFound(host_id)
        entity.host = entities[host_id]

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            if parent_id not in entities:
                raise EntityNotFound(parent_id)
            entity.service = entities[parent_id]

    def add_relationships_from_db(self, entity, session):
        couchdb_id = entity.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        entity.host = query.one()

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            query = session.query(Service).join(EntityMetadata).filter(EntityMetadata.couchdb_id == parent_id)
            entity.service = query.one()


class CommandImporter(object):
    DOC_TYPE = 'CommandRunInformation'

    @classmethod
    def update_from_document(cls, document):
        command, instance = get_or_create(session, Command, command=document.get('command', None))
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

    def add_relationships_from_dict(self, entity, entities):
        # this method is not required since update_from_document uses
        # workspace name to create the relation
        pass


class NoteImporter(object):
    DOC_TYPE = 'Note'

    @classmethod
    def update_from_document(cls, document):
        note = Note()
        note.name = document.get('name')
        note.text = document.get('text', None)
        note.description = document.get('description', None)
        note.owned = document.get('owned', False)
        return note

    def add_relationships_from_dict(self, entity, entities):
        # this method is not required since update_from_document uses
        # workspace name to create the relation
        pass


class CredentialImporter(object):
    DOC_TYPE = 'Cred'

    @classmethod
    def update_from_document(cls, document):
        credential = Credential()
        credential.username = document.get('username')
        credential.password = document.get('password', '')
        credential.owned = document.get('owned', False)
        credential.description = document.get('description', '')
        credential.name = document.get('name', '')
        return credential

    def add_relationships_from_dict(self, entity, entities):
        couchdb_id = entity.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        if host_id not in entities:
            raise EntityNotFound(host_id)
        entity.host = entities[host_id]

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            if parent_id not in entities:
                raise EntityNotFound(parent_id)
            entity.service = entities[parent_id]

    def add_relationships_from_db(self, entity, session):
        couchdb_id = entity.entity_metadata.couchdb_id
        host_id = couchdb_id.split('.')[0]
        query = session.query(Host).join(EntityMetadata).filter(EntityMetadata.couchdb_id == host_id)
        entity.host = query.one()

        parent_id = '.'.join(couchdb_id.split('.')[:-1])
        if parent_id != host_id:
            query = session.query(Service).join(EntityMetadata).filter(EntityMetadata.couchdb_id == parent_id)
            entity.service = query.one()


class WorkspaceImporter(object):
    DOC_TYPE = 'Workspace'

    @classmethod
    def update_from_document(cls, document):
        workspace = Workspace()
        workspace.name = document.get('name', None)
        return workspace

    def add_relationships_from_dict(self, entity, entities):
        for couch_id, child_entity in entities.items():
            child_entity.workspace = entity



class FaradayEntityImporter(object):
    # Document Types: [u'Service', u'Communication', u'Vulnerability', u'CommandRunInformation', u'Reports', u'Host', u'Workspace', u'Interface']
    @classmethod
    def parse(cls, document):
        """Get an instance of a DAO object given a document"""
        importer_class = cls.get_importer_from_document(document)
        if importer_class is not None:
            importer = importer_class()
            entity = importer.update_from_document(document)
            metadata = EntityMetadataImporter().update_from_document(document)
            entity.entity_metadata = metadata
            return importer, entity
        return None, None

    @classmethod
    def get_importer_from_document(cls, document):
        doc_type = document.get('type')
        if not doc_type:
            return
        importer_class_mapper = {
            'EntityMetadata': EntityMetadataImporter,
            'Host': HostImporter,
            'Interface': InterfaceImporter,
            'Service': ServiceImporter,
            'Note': NoteImporter,
            'CommandRunInformation': CommandImporter,
            'Workspace': WorkspaceImporter,
            'Vulnerability': VulnerabilityImporter,
            'VulnerabilityWeb': VulnerabilityImporter,
        }
        if doc_type in ('Communication', 'Cred', 'Reports',
                        'Task', 'TaskGroup'):
            return
        importer_cls = importer_class_mapper.get(doc_type, None)
        if not importer_cls:
            raise NotImplementedError('Class importer for {0} not implemented'.format(doc_type))
        return importer_cls

    @classmethod
    def update_from_document(self, document):
        raise Exception('MUST IMPLEMENT')


def import_workspaces():
    """
        Main entry point for couchdb import
    """
    app = server.app.create_app()
    app.app_context().push()
    db.create_all()

    couchdb_server_conn, workspaces_list = _open_couchdb_conn()

    for workspace_name in workspaces_list:
        logger.info(u'Setting up workspace {}'.format(workspace_name))

        if not server.couchdb.server_has_access_to(workspace_name):
            logger.error(u"Unauthorized access to CouchDB. Make sure faraday-server's"\
                         " configuration file has CouchDB admin's credentials set")
            sys.exit(1)

        import_workspace_into_database(workspace_name, couchdb_server_conn=couchdb_server_conn)


def _open_couchdb_conn():
    try:
        couchdb_server_conn = server.couchdb.CouchDBServer()
        workspaces_list = couchdb_server_conn.list_workspaces()

    except RequestError:
        logger.error(u"CouchDB is not running at {}. Check faraday-server's"\
            " configuration and make sure CouchDB is running".format(
            server.couchdb.get_couchdb_url()))
        sys.exit(1)

    except Unauthorized:
        logger.error(u"Unauthorized access to CouchDB. Make sure faraday-server's"\
            " configuration file has CouchDB admin's credentials set")
        sys.exit(1)

    return couchdb_server_conn, workspaces_list


def import_workspace_into_database(workspace_name, couchdb_server_conn):
    workspace, created = get_or_create(session, server.models.Workspace, name=workspace_name)
    try:
        # import checks if the object exists.
        # the import is idempotent
        _import_from_couchdb(workspace, couchdb_server_conn)
        session.commit()
    except Exception as ex:
        import traceback
        traceback.print_exc()
        logger.exception(ex)
        session.rollback()
        raise ex

    return created


def _import_from_couchdb(workspace, couchdb_conn):
    couchdb_workspace = server.couchdb.CouchDBWorkspace(workspace.name, couchdb_server_conn=couchdb_conn)
    total_amount = couchdb_workspace.get_total_amount_of_documents()
    processed_docs, progress = 0, 0
    should_flush_changes = False
    host_entities = {}

    def flush_changes():
        host_entities.clear()
        session.commit()
        session.expunge_all()

    for doc in tqdm(couchdb_workspace.get_documents(per_request=1000), total=total_amount):
        processed_docs = processed_docs + 1
        entity_data = doc.get('doc')
        importer, entity = FaradayEntityImporter.parse(entity_data)
        if entity is not None:
            if isinstance(entity, server.models.Host) and should_flush_changes:
                flush_changes()
                should_flush_changes = False

            try:
                importer.add_relationships_from_dict(entity, host_entities)
            except EntityNotFound:
                logger.warning(u"Ignoring {} entity ({}) because its parent wasn't found".format(
                    entity.entity_metadata.document_type, entity.entity_metadata.couchdb_id))
            else:
                host_entities[doc.get('key')] = entity
                session.add(entity)

    logger.info(u'{} importation done!'.format(workspace.name))
    flush_changes()
