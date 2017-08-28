# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import sys
import json
import os

import requests
from tqdm import tqdm
from flask_script import Command as FlaskScriptCommand
from restkit.errors import RequestError, Unauthorized

import server.app
import server.utils.logger
import server.couchdb
import server.database
import server.models
import server.config
from server.utils.database import get_or_create
from server.models import (
    db,
    EntityMetadata,
    Credential,
    Host,
    Service,
    Command,
    Workspace,
    Vulnerability
)


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
    def update_from_document(cls, document, workspace):
        # Ticket #3387: if the 'os' field is None, we default to 'unknown'
        host, created = get_or_create(session, Host, name=document.get('name'))
        if not document.get('os'):
            document['os'] = 'unknown'

        default_gateway = document.get('default_gateway', None)

        host.name = document.get('name')
        host.description = document.get('description')
        host.os = document.get('os')
        host.default_gateway_ip = default_gateway and default_gateway[0] or ''
        host.default_gateway_mac = default_gateway and default_gateway[1] or ''
        host.owned = document.get('owned', False)
        host.workspace = workspace
        return host

    def set_parent(self, host, parent):
        raise NotImplementedError


class InterfaceImporter(object):
    DOC_TYPE = 'Interface'

    @classmethod
    def update_from_document(cls, document, workspace):
        interface, created = get_or_create(session, Interface, name=document.get('name'))
        interface.name = document.get('name')
        interface.description = document.get('description')
        interface.mac = document.get('mac')
        interface.owned = document.get('owned', False)
        interface.hostnames = u','.join(document.get('hostnames') or [])
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
        interface.workspace = workspace
        return interface

    @classmethod
    def set_parent(cls, interface, parent_relation_db_id, level):
        interface.host = session.query(Host).filter_by(id=parent_relation_db_id).first()


class ServiceImporter(object):
    DOC_TYPE = 'Service'

    @classmethod
    def update_from_document(cls, document, workspace):
        service, created = get_or_create(session, Service, name=document.get('name'))
        service.name = document.get('name')
        service.description = document.get('description')
        service.owned = document.get('owned', False)
        service.protocol = document.get('protocol')
        service.status = document.get('status')
        service.version = document.get('version')
        service.workspace = workspace

        # We found workspaces where ports are defined as an integer
        if isinstance(document.get('ports', None), (int, long)):
            service.ports = str(document.get('ports'))
        else:
            service.ports = u','.join(map(str, document.get('ports')))
        return service

    def set_parent(self, service, parent_id):
        raise NotImplementedError


class VulnerabilityImporter(object):
    DOC_TYPE = ['Vulnerability', 'VulnerabilityWeb']

    @classmethod
    def update_from_document(cls, document, workspace):
        vulnerability, created = get_or_create(session, Vulnerability, name=document.get('name'), description= document.get('desc'))
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
        vulnerability.workspace = workspace

        params = document.get('params', u'')
        if isinstance(params, (list, tuple)):
            vulnerability.params = (u' '.join(params)).strip()
        else:
            vulnerability.params = params if params is not None else u''

        return vulnerability

    @classmethod
    def set_parent(self, vulnerability, parent_id, level=2):
        logger.debug('Set parent for vulnerabiity level {0}'.format(level))
        if level == 2:
            vulnerability.host = session.query(Host).filter_by(id=parent_id).first()
        if level == 3:
            vulnerability.service = session.query(Service).filter_by(id=parent_id).first()

class CommandImporter(object):
    DOC_TYPE = 'CommandRunInformation'

    @classmethod
    def update_from_document(cls, document, workspace):
        command, instance = get_or_create(session, Command, command=document.get('command', None))
        command.command = document.get('command', None)
        command.duration = document.get('duration', None)
        command.itime = document.get('itime', None)
        command.ip = document.get('ip', None)
        command.hostname = document.get('hostname', None)
        command.params = document.get('params', None)
        command.user = document.get('user', None)
        command.workspace = workspace

        return command

    def set_parent(self, command, parent_id):
        raise NotImplementedError


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
    def update_from_document(cls, document, workspace):
        credential, created = get_or_create(session, Credential, name=document.get('username'))
        credential.username = document.get('username')
        credential.password = document.get('password', '')
        credential.owned = document.get('owned', False)
        credential.description = document.get('description', '')
        credential.name = document.get('name', '')
        credential.workspace = workspace
        return credential

    def set_parent(self, credential, parent_id):
        raise NotImplementedError


class WorkspaceImporter(object):
    DOC_TYPE = 'Workspace'

    @classmethod
    def update_from_document(cls, document):
        workspace, created = get_or_create(session, server.models.Workspace, name=document.get('name', None))
        return workspace

    def add_relationships_from_dict(self, entity, entities):
        for couch_id, child_entity in entities.items():
            child_entity.workspace = entity


class FaradayEntityImporter(object):
    # Document Types: [u'Service', u'Communication', u'Vulnerability', u'CommandRunInformation', u'Reports', u'Host', u'Workspace']
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
    def get_importer_from_document(cls, doc_type):
        logger.info('Getting class importer for {0}'.format(doc_type))
        importer_class_mapper = {
            'EntityMetadata': EntityMetadataImporter,
            'Host': HostImporter,
            'Service': ServiceImporter,
            'Note': NoteImporter,
            'CommandRunInformation': CommandImporter,
            'Workspace': WorkspaceImporter,
            'Vulnerability': VulnerabilityImporter,
            'VulnerabilityWeb': VulnerabilityImporter,
        }
        # TODO: remove this!
        if doc_type in ('Communication', 'Cred', 'Reports',
                        'Task', 'TaskGroup', 'Interface', 'Note'):
            return
        importer_cls = importer_class_mapper.get(doc_type, None)
        if not importer_cls:
            raise NotImplementedError('Class importer for {0} not implemented'.format(doc_type))
        return importer_cls

    @classmethod
    def update_from_document(self, document):
        raise Exception('MUST IMPLEMENT')


class ImportCouchDB(FlaskScriptCommand):

    def _open_couchdb_conn(self):
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

    def run(self):
        """
            Main entry point for couchdb import
        """
        couchdb_server_conn, workspaces_list = self._open_couchdb_conn()

        for workspace_name in workspaces_list:
            logger.info(u'Setting up workspace {}'.format(workspace_name))

            if not server.couchdb.server_has_access_to(workspace_name):
                logger.error(u"Unauthorized access to CouchDB. Make sure faraday-server's"\
                             " configuration file has CouchDB admin's credentials set")
                sys.exit(1)

            self.import_workspace_into_database(workspace_name)

    def get_objs(self, host, obj_type, level):
        data = {
            "map": "function(doc) { if(doc.type == '%s' && doc._id.split('.').length == %d) emit(null, doc); }" % (obj_type, level)
        }

        r = requests.post(host, json=data)

        return r.json()

    def import_workspace_into_database(self, workspace_name):

        faraday_importer = FaradayEntityImporter()
        workspace, created = get_or_create(session, server.models.Workspace, name=workspace_name)

        couch_url = "http://{username}:{password}@{hostname}:{port}/{workspace_name}/_temp_view?include_docs=true".format(
                    username=server.config.couchdb.user,
                    password=server.config.couchdb.password,
                    hostname=server.config.couchdb.host,
                    port=server.config.couchdb.port,
                    workspace_name=workspace_name
                )

        obj_types = [
            (1, 'Host'),
            (1, 'EntityMetadata'),
            (1, 'Note'),
            (1, 'CommandRunInformation'),
            (2, 'Interface'),
            (2, 'Service'),
            (2, 'Vulnerability'),
            (2, 'VulnerabilityWeb'),
            (3, 'Vulnerability'),
            (3, 'VulnerabilityWeb'),
        ]
        couchdb_relational_map = {}

        for level, obj_type in obj_types:
            obj_importer = faraday_importer.get_importer_from_document(obj_type)
            objs_dict = self.get_objs(couch_url, obj_type, level)
            for raw_obj in tqdm(objs_dict.get('rows', [])):
                raw_obj = raw_obj['value']
                couchdb_id = raw_obj['_id']
                new_obj = obj_importer.update_from_document(raw_obj, workspace)
                if raw_obj.get('parent', None):
                    obj_importer.set_parent(
                        new_obj,
                        couchdb_relational_map[raw_obj['parent']],
                        level
                    )
                session.commit()
                couchdb_relational_map[couchdb_id] = new_obj.id

        return created
