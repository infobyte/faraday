# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import sys
import json
import datetime
from binascii import unhexlify

import requests
from tqdm import tqdm
from flask_script import Command as FlaskScriptCommand
from restkit.errors import RequestError, Unauthorized
from IPy import IP
from passlib.utils.binary import ab64_encode
from passlib.hash import pbkdf2_sha1

from server.web import app
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
    Hostname,
    Vulnerability
)

COUCHDB_USER_PREFIX = 'org.couchdb.user:'
COUCHDB_PASSWORD_PREXFIX = '-pbkdf2-'


logger = server.utils.logger.get_logger(__name__)
session = db.session


class EntityNotFound(Exception):
    def __init__(self, entity_id):
        super(EntityNotFound, self).__init__("Entity (%s) wasn't found" % entity_id)


class EntityMetadataImporter(object):

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
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
            entity.create_time = self.__truncate_to_epoch_in_seconds(entity.create_time)

        yield entity

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

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        # Ticket #3387: if the 'os' field is None, we default to 'unknown'
        host, created = get_or_create(session, Host, ip=document.get('name'))
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
        yield host


class InterfaceImporter(object):
    """
        Class interface was removed in the new model.
        We will merge the interface data with the host.
        For ports we will create new services for open ports
        if it was not previously created.
    """
    DOC_TYPE = 'Interface'

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):

        interface = {}
        interface['name'] = document.get('name')
        interface['description'] = document.get('description')
        interface['mac'] = document.get('mac')
        interface['owned'] = document.get('owned', False)
        interface['hostnames'] = document.get('hostnames')
        interface['network_segment'] = document.get('network_segment')
        interface['ipv4_address'] = document.get('ipv4').get('address')
        interface['ipv4_gateway'] = document.get('ipv4').get('gateway')
        interface['ipv4_dns'] = document.get('ipv4').get('DNS')
        interface['ipv4_mask'] = document.get('ipv4').get('mask')
        interface['ipv6_address'] = document.get('ipv6').get('address')
        interface['ipv6_gateway'] = document.get('ipv6').get('gateway')
        interface['ipv6_dns'] = document.get('ipv6').get('DNS')
        interface['ipv6_prefix'] = str(document.get('ipv6').get('prefix'))
        # ports_* are integers with counts
        interface['ports_filtered'] = document.get('ports', {}).get('filtered')
        interface['ports_opened'] = document.get('ports', {}).get('opened')
        interface['ports_closed'] = document.get('ports', {}).get('closed')
        interface['workspace'] = workspace
        couch_parent_id = document.get('parent', None)
        if not couch_parent_id:
            couch_parent_id = '.'.join(document['_id'].split('.')[:-1])
        parent_id = couchdb_relational_map[couch_parent_id]
        self.merge_with_host(interface, parent_id)
        yield interface

    def merge_with_host(self, interface, parent_relation_db_id):
        host = session.query(Host).filter_by(id=parent_relation_db_id).first()
        assert host.workspace == interface['workspace']
        if interface['mac']:
            host.mac = interface['mac']
        if interface['owned']:
            host.owned = interface['owned']
        if interface['ipv4_address'] or interface['ipv6_address']:
            host.ip = interface['ipv4_address'] or interface['ipv6_address']
        if interface['ipv4_gateway'] or interface['ipv6_gateway']:
            host.default_gateway_ip = interface['ipv4_gateway'] or interface['ipv6_gateway']
        #host.default_gateway_mac
        if interface['network_segment']:
            host.net_segment = interface['network_segment']
        if interface['description']:
            host.description += '\n {0}'.format(interface['description'])

        for hostname in interface['hostnames']:
            hostname, created = get_or_create(session, Hostname, name=hostname, host=host)
        host.owned = host.owned or interface['owned']


class ServiceImporter(object):
    DOC_TYPE = 'Service'

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        #  service was always above interface, not it's above host.
        try:
            parent_id = document['parent'].split('.')[0]
        except KeyError:
            # some services are missing the parent key
            parent_id = document['_id'].split('.')[0]
        host, created = get_or_create(session, Host, id=couchdb_relational_map[parent_id])
        for port in document.get('ports'):
            service, created = get_or_create(session, Service, name=document.get('name'), port=port)
            service.name = document.get('name')
            service.description = document.get('description')
            service.owned = document.get('owned', False)
            service.protocol = document.get('protocol')
            if not document.get('status'):
                logger.warning('Service {0} with empty status. Using open as status'.format(document['_id']))
                document['status'] = 'open'
            status_mapper = {
                'open': 'open',
                'closed': 'closed',
                'filtered': 'filtered'
            }
            service.status = status_mapper[document.get('status')]
            service.version = document.get('version')
            service.workspace = workspace

            yield service


class VulnerabilityImporter(object):
    DOC_TYPE = ['Vulnerability', 'VulnerabilityWeb']

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
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
        status_map = {
            'opened': 'open',
            'closed': 'closed',
        }
        status = status_map[document.get('status', 'opened')]
        vulnerability.status = status
        vulnerability.workspace = workspace

        params = document.get('params', u'')
        if isinstance(params, (list, tuple)):
            vulnerability.params = (u' '.join(params)).strip()
        else:
            vulnerability.params = params if params is not None else u''

        couch_parent_id = document.get('parent', None)
        if not couch_parent_id:
            couch_parent_id = '.'.join(document['_id'].split('.')[:-1])
        parent_id = couchdb_relational_map[couch_parent_id]
        self.set_parent(vulnerability, parent_id, level)
        yield vulnerability

    def set_parent(self, vulnerability, parent_id, level=2):
        logger.debug('Set parent for vulnerabiity level {0}'.format(level))
        if level == 2:
            vulnerability.host = session.query(Host).filter_by(id=parent_id).first()
        if level == 3:
            vulnerability.service = session.query(Service).filter_by(id=parent_id).first()


class CommandImporter(object):
    DOC_TYPE = 'CommandRunInformation'

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        start_date = datetime.datetime.fromtimestamp(document.get('itime'))
        end_date = start_date + datetime.timedelta(seconds=document.get('duration'))
        command, instance = get_or_create(
                session,
                Command,
                command=document.get('command', None),
                start_date=start_date,
                end_date=end_date
        )
        command.command = document.get('command', None)
        command.ip = document.get('ip', None)
        command.hostname = document.get('hostname', None)
        command.params = document.get('params', None)
        command.user = document.get('user', None)
        command.workspace = workspace

        yield command


class NoteImporter(object):
    DOC_TYPE = 'Note'

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        note = Note()
        note.name = document.get('name')
        note.text = document.get('text', None)
        note.description = document.get('description', None)
        note.owned = document.get('owned', False)
        yield note


class CredentialImporter(object):
    DOC_TYPE = 'Cred'

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        host = None
        service = None
        if level == 2:
            parent_id = couchdb_relational_map[document['_id'].split('.')[0]]
            host = session.query(Host).filter_by(id=parent_id).first()
        if level == 4:
            parent_id = couchdb_relational_map['.'.join(document['_id'].split('.')[:3])]
            service = session.query(Service).filter_by(id=parent_id).first()
        if not host and not service:
            raise Exception('Missing host or service for credential {0}'.format(document['_id']))
        credential, created = get_or_create(session, Credential, username=document.get('username'), host=host, service=service)
        credential.password = document.get('password', None)
        credential.owned = document.get('owned', False)
        credential.description = document.get('description', None)
        credential.name = document.get('name', None)
        credential.workspace = workspace
        yield credential


class WorkspaceImporter(object):
    DOC_TYPE = 'Workspace'

    def update_from_document(self, document):
        workspace, created = get_or_create(session, server.models.Workspace, name=document.get('name', None))
        yield workspace


class FaradayEntityImporter(object):
    # Document Types: [u'Service', u'Communication', u'Vulnerability', u'CommandRunInformation', u'Reports', u'Host', u'Workspace']

    def parse(self, document):
        """Get an instance of a DAO object given a document"""
        importer_class = self.get_importer_from_document(document)
        if importer_class is not None:
            importer = importer_class()
            entity = importer.update_from_document(document)
            metadata = EntityMetadataImporter().update_from_document(document)
            entity.entity_metadata = metadata
            return importer, entity
        return None, None

    def get_importer_from_document(self, doc_type):
        logger.info('Getting class importer for {0}'.format(doc_type))
        importer_class_mapper = {
            'EntityMetadata': EntityMetadataImporter,
            'Host': HostImporter,
            'Service': ServiceImporter,
            'Note': NoteImporter,
            'Credential': CredentialImporter,
            'Interface': InterfaceImporter,
            'CommandRunInformation': CommandImporter,
            'Workspace': WorkspaceImporter,
            'Vulnerability': VulnerabilityImporter,
            'VulnerabilityWeb': VulnerabilityImporter,
        }
        importer_self = importer_class_mapper.get(doc_type, None)
        if not importer_self:
            raise NotImplementedError('Class importer for {0} not implemented'.format(doc_type))
        return importer_self


class ImportCouchDBUsers(FlaskScriptCommand):

    def modular_crypt_pbkdf2_sha1(self, checksum, salt, iterations=1000):
        return '$pbkdf2${iterations}${salt}${checksum}'.format(
            iterations=iterations,
            salt=ab64_encode(salt),
            checksum=ab64_encode(unhexlify(checksum)),
        )

    def convert_couchdb_hash(self, original_hash):
        if not original_hash.startswith(COUCHDB_PASSWORD_PREXFIX):
            # Should be a plaintext password
            return original_hash
        checksum, salt, iterations = original_hash[
            len(COUCHDB_PASSWORD_PREXFIX):].split(',')
        iterations = int(iterations)
        return self.modular_crypt_pbkdf2_sha1(checksum, salt, iterations)

    def get_hash_from_document(self, doc):
        scheme = doc.get('password_scheme', 'unset')
        if scheme != 'pbkdf2':
            raise ValueError('Unknown password scheme: %s' % scheme)
        return self.modular_crypt_pbkdf2_sha1(doc['derived_key'], doc['salt'],
                                         doc['iterations'])

    def parse_all_docs(self, doc):
        return [row['doc'] for row in doc['rows']]

    def get_users_and_admins(self):
        admins_url = "http://{username}:{password}@{hostname}:{port}/{path}".format(
                    username=server.config.couchdb.user,
                    password=server.config.couchdb.password,
                    hostname=server.config.couchdb.host,
                    port=server.config.couchdb.port,
                    path='_config/admins'
        )

        users_url = "http://{username}:{password}@{hostname}:{port}/{path}".format(
                    username=server.config.couchdb.user,
                    password=server.config.couchdb.password,
                    hostname=server.config.couchdb.host,
                    port=server.config.couchdb.port,
                    path='_users/_all_docs?include_docs=true'
        )
        admins = requests.get(admins_url).json()
        users = requests.get(users_url).json()
        return users, admins

    def import_admins(self, admins):
        # Import admin users
        for (username, password) in admins.items():
            logger.info('Creating user {0}'.format(username))
            app.user_datastore.create_user(
                username=username,
                email=username + '@test.com',
                password=self.convert_couchdb_hash(password),
                is_ldap=False
            )

    def import_users(self, all_users, admins):
        # Import non admin users
        for user in all_users['rows']:
            user = user['doc']
            if not user['_id'].startswith(COUCHDB_USER_PREFIX):
                # It can be a view or something other than a user
                continue
            if user['name'] in admins.keys():
                # This is an already imported admin user, skip
                continue
            logger.info('Importing {0}'.format(user['name']))
            app.user_datastore.create_user(
                username=user['name'],
                email=user['name'] + '@test.com',
                password=self.get_hash_from_document(user),
                is_ldap=False
            )

    def run(self):
        all_users, admins = self.get_users_and_admins()
        self.import_users(all_users, admins)
        self.import_admins(admins)
        db.session.commit()


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
        users_import = ImportCouchDBUsers()
        users_import.run()
        couchdb_server_conn, workspaces_list = self._open_couchdb_conn()

        for workspace_name in workspaces_list:
            logger.info(u'Setting up workspace {}'.format(workspace_name))

            if not server.couchdb.server_has_access_to(workspace_name):
                logger.error(u"Unauthorized access to CouchDB. Make sure faraday-server's"\
                             " configuration file has CouchDB admin's credentials set")
                sys.exit(1)

            self.import_workspace_into_database(workspace_name)

    def get_objs(self, host, obj_type, level):
        if obj_type == 'Credential':
            obj_type = 'Cred'
        data = {
            "map": "function(doc) { if(doc.type == '%s' && doc._id.split('.').length == %d) emit(null, doc); }" % (obj_type, level)
        }

        r = requests.post(host, json=data)

        return r.json()

    def verify_import_data(self, couchdb_relational_map, couchdb_removed_objs, workspace):
        all_docs_url = "http://{username}:{password}@{hostname}:{port}/{workspace_name}/_all_docs?include_docs=true".format(
                    username=server.config.couchdb.user,
                    password=server.config.couchdb.password,
                    hostname=server.config.couchdb.host,
                    port=server.config.couchdb.port,
                    workspace_name=workspace.name
        )
        all_ids = map(lambda x: x['doc']['_id'], requests.get(all_docs_url).json()['rows'])
        if len(all_ids) != len(couchdb_relational_map.keys()) + len(couchdb_removed_objs):
            missing_objs_filename = os.path.join(os.path.expanduser('~/.faraday'), 'logs', 'import_missing_objects_{0}.json'.format(workspace.name))
            logger.warning('Not all objects were imported. Saving difference to file {0}'.format(missing_objs_filename))
            missing_ids = set(all_ids) - set(couchdb_relational_map.keys()).union(couchdb_removed_objs)
            objs_diff = []
            logger.info('Downloading missing couchdb docs')
            for missing_id in tqdm(missing_ids):
                doc_url = 'http://{username}:{password}@{hostname}:{port}/{workspace_name}/{doc_id}'.format(
                    username=server.config.couchdb.user,
                    password=server.config.couchdb.password,
                    hostname=server.config.couchdb.host,
                    port=server.config.couchdb.port,
                    workspace_name=workspace.name,
                    doc_id=missing_id
                )
                objs_diff.append(requests.get(doc_url).json())

            with open(missing_objs_filename, 'w') as missing_objs_file:
                missing_objs_file.write(json.dumps(objs_diff))

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

        # obj_types are tuples. the first value is the level on the tree
        # for the desired obj.
        # the idea is to improt by level from couchdb data.
        obj_types = [
            (1, 'Host'),
            (1, 'EntityMetadata'),
            (1, 'Note'),
            (1, 'CommandRunInformation'),
            (2, 'Interface'),
            (2, 'Service'),
            (2, 'Credential'),
            (2, 'Vulnerability'),
            (2, 'VulnerabilityWeb'),
            (3, 'Vulnerability'),
            (3, 'VulnerabilityWeb'),
            (3, 'Service'),
            (4, 'Credential'),  # Level 4 is for interface
        ]
        couchdb_relational_map = {}
        couchdb_removed_objs = set()
        removed_objs = ['Interface']
        for level, obj_type in obj_types:
            obj_importer = faraday_importer.get_importer_from_document(obj_type)()
            objs_dict = self.get_objs(couch_url, obj_type, level)
            for raw_obj in tqdm(objs_dict.get('rows', [])):
                raw_obj = raw_obj['value']
                couchdb_id = raw_obj['_id']
                for new_obj in obj_importer.update_from_document(raw_obj, workspace, level, couchdb_relational_map):
                    session.commit()
                    if obj_type not in removed_objs:
                        couchdb_relational_map[couchdb_id] = new_obj.id
                    else:
                        couchdb_removed_objs.add(couchdb_id)
        self.verify_import_data(couchdb_relational_map, couchdb_removed_objs, workspace)
        return created
