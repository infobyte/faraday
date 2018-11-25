# -*- coding: utf8 -*-
# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import string
from random import SystemRandom

import os
import re
import sys
import json
import logging
import datetime
import multiprocessing


import requests
from requests.exceptions import HTTPError, RequestException
from tempfile import NamedTemporaryFile

from collections import (
    Counter,
    defaultdict,
    OrderedDict
)
from slugify import slugify
from sqlalchemy import Text, String
from binascii import unhexlify
try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

from IPy import IP
from passlib.utils.binary import ab64_encode
from tqdm import tqdm
import server.config

import server.models
import server.utils.logger
from server.models import (
    db,
    Command,
    CommandObject,
    Comment,
    Credential,
    ExecutiveReport,
    Host,
    Hostname,
    License,
    Methodology,
    MethodologyTemplate,
    PolicyViolation,
    Reference,
    Service,
    Scope,
    Tag,
    TagObject,
    Task,
    TaskTemplate,
    User,
    Vulnerability,
    VulnerabilityTemplate,
    VulnerabilityWeb,
    Workspace,
    WorkspacePermission,
    File,
)
from server.utils import invalid_chars
from server.utils.database import get_or_create
from server.web import app

COUCHDB_USER_PREFIX = 'org.couchdb.user:'
COUCHDB_PASSWORD_PREFIX = '-pbkdf2-'

logger = server.utils.logger.get_logger(__name__)

importer_logfile = os.path.expanduser(os.path.join(
    server.config.CONSTANTS.CONST_FARADAY_HOME_PATH,
    server.config.CONSTANTS.CONST_FARADAY_LOGS_PATH, 'couchdb-importer.log'))
importer_file_handler = logging.FileHandler(importer_logfile)
formatter = logging.Formatter(
        '%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s')
importer_file_handler.setFormatter(formatter)
importer_file_handler.setLevel(logging.DEBUG)
logger.addHandler(importer_file_handler)


session = db.session

MAPPED_VULN_SEVERITY = OrderedDict([
    ('critical', 'critical'),
    ('high', 'high'),
    ('med', 'medium'),
    ('low', 'low'),
    ('info', 'informational'),
    ('unclassified', 'unclassified'),
    ('unknown', 'unclassified'),
    ('', 'unclassified'),
])

# The objects are imported in this order (the order of the list, the integer
# isn't related to this)
OBJ_TYPES = [
            (1, 'CommandRunInformation'),
            (1, 'Host'),
            (1, 'EntityMetadata'),
            (1, 'Note'),
            (1, 'TaskGroup'),
            (1, 'Task'),
            (1, 'Workspace'),
            (1, 'Reports'),
            (1, 'Communication'),
            (1, 'Note'),
            (2, 'Service'),
            (2, 'Credential'),
            (2, 'Vulnerability'),
            (2, 'VulnerabilityWeb'),
            (3, 'Service'),
            (4, 'Credential'),  # Level 4 is for interface
            (4, 'Vulnerability'),
            (4, 'VulnerabilityWeb'),
        ]


# Really ugly hack to avoid setting to null non-nullable text columns
for model in (
        Command,
        CommandObject,
        Comment,
        Credential,
        ExecutiveReport,
        Host,
        Hostname,
        License,
        Methodology,
        MethodologyTemplate,
        PolicyViolation,
        Reference,
        Service,
        Scope,
        Tag,
        TagObject,
        Task,
        TaskTemplate,
        User,
        Vulnerability,
        VulnerabilityWeb,
        VulnerabilityTemplate,
        Workspace,
        File,
        ):
    old_setattr = model.__setattr__

    def __setattr__(self, key, value):
        assert self.__table__ is not None
        try:
            column = self.__table__.columns[key]
        except KeyError:
            pass
        else:
            if (isinstance(column.type, (Text, String))
                    and not column.nullable
                    and value is None):
                value = ''
        return old_setattr(self, key, value)

    model.__setattr__ = __setattr__


def get_object_from_couchdb(couchdb_id, workspace):
    doc_url = 'http://{username}:{password}@{hostname}:{port}/{workspace_name}/{doc_id}'.format(
        username=server.config.couchdb.user,
        password=server.config.couchdb.password,
        hostname=server.config.couchdb.host,
        port=server.config.couchdb.port,
        workspace_name=workspace.name,
        doc_id=couchdb_id
    )
    return requests.get(doc_url).json()


def get_children_from_couch(workspace, parent_couchdb_id, child_type):
    """
    Performance for temporary views suck, so this method uploads a view and queries it instead

    :param workspace: workspace to upload the view
    :param parent_couchdb_id: ID of the parent document
    :param child_type: type of the child obj we're looking for
    :return:
    """

    couch_url = "http://{username}:{password}@{hostname}:{port}/{workspace_name}/".format(
        username=server.config.couchdb.user,
        password=server.config.couchdb.password,
        hostname=server.config.couchdb.host,
        port=server.config.couchdb.port,
        workspace_name=workspace.name,
    )

    # create the new view
    view_url = "{}_design/importer".format(couch_url)
    view_data = {
        "views": {
            "children_by_parent_and_type": {
                "map":
                    "function(doc) { id_parent = doc._id.split('.').slice(0, -1).join('.');"
                    "key = [id_parent,doc.type]; emit(key, doc); }"
            }
        }
    }

    try:
        r = requests.put(view_url, json=view_data)
    except RequestException as e:
        logger.exception(e)
        return []

    # and now, finally query it!
    couch_url += "_design/importer/_view/children_by_parent_and_type?" \
                 "startkey=[\"{parent_id}\",\"{child_type}\"]&" \
                 "endkey=[\"{parent_id}\",\"{child_type}\"]".format(
        parent_id=parent_couchdb_id,
        child_type=child_type,
    )

    try:
        r = requests.get(couch_url)
    except RequestException as e:
        logger.error('Network error in CouchDB request {}'.format(
            couch_url,
            r.status_code,
            r.text))
        logger.exception(e)
        return []

    try:
        r.raise_for_status()
    except RequestException as e:
        logger.error('Error in CouchDB request {}. '
                     'Status code: {}. '
                     'Body: {}'.format(couch_url,
                                       r.status_code,
                                       r.text))
        logger.exception(e)
        return []

    return r.json()['rows']


def create_tags(raw_tags, parent_id, parent_type):
    for tag_name in [x.strip() for x in raw_tags if x.strip()]:
        tag, tag_created = get_or_create(session, Tag, slug=slugify(tag_name))
        tag.name = tag_name
        session.commit()
        parent_type = parent_type.lower()
        parent_type = parent_type.replace('web', '')
        relation, relation_created = get_or_create(
            session,
            TagObject,
            object_id=parent_id,
            object_type=parent_type,
            tag_id=tag.id,
        )
        session.commit()


def set_metadata(document, obj):
    if 'metadata' in document:
        for key, value in document['metadata'].iteritems():
            if not value:
                continue
            try:
                if key == 'create_time':
                    obj.create_date = datetime.datetime.fromtimestamp(document['metadata']['create_time'])
                    if obj.create_date > datetime.datetime.now():
                        raise Exception('Invalid date!')
                if key == 'owner':
                    creator = User.query.filter_by(username=value).first()
                    obj.creator = creator
            except ValueError:
                if key == 'create_time':
                    obj.create_date = datetime.datetime.fromtimestamp(document['metadata']['create_time'] / 1000)
            except TypeError:
                print('')


def map_tool_with_command_id(command_tool_map, document):
    try:
        metadata = document['metadata']
        tool = metadata['creator']
        command_id = metadata['command_id']
    except KeyError:
        # Ignore objects without any of these keys
        return
    if not tool or not command_id:
        # it could be blank
        return
    old_tool = command_tool_map.get(command_id)
    if old_tool is not None and old_tool != tool:
        logger.warn('Conflicting tool names for command {}: "{}" and "{}". '
                    'Using "{}"'.format(
                        command_id,
                        old_tool,
                        tool,
                        tool
                    ))
    command_tool_map[command_id] = tool


def update_command_tools(workspace, command_tool_map, id_map):
    if command_tool_map:
        logger.debug("Setting the tool to {} commands".format(
            len(command_tool_map)))
    for (command_couchid, tool) in (command_tool_map.items()):
        try:
            map_data = id_map[command_couchid]

            # There should be only one command created
            assert len(map_data) <= 1
            map_data = map_data[0]
        except IndexError:
            logger.warn("Couldn't find new numeric ID of command {}".format(
                command_couchid
            ))
            continue
        else:
            assert map_data['type'] == 'CommandRunInformation'
            command_id = map_data['id']
        command = Command.query.get(command_id)
        if command is None:
            logger.warn("Couldn't get command {}, mapped to ID {}".format(
                command_couchid,
                command_id
            ))
            continue
        assert workspace.id == command.workspace_id, (workspace.id, command.workspace_id)
        if command.tool and command.tool != 'unknown':
            logger.warn("Command {} (Couch ID {}) has already a tool. "
                        "Overriding it".format(command_id,
                                               command_couchid))
        command.tool = tool
        session.add(command)
    session.commit()
    missing_tool_count = Command.query.filter_by(
        workspace=workspace, tool="unknown").count()
    if missing_tool_count:
        logger.debug("Couldn't find the tool name of {} commands in "
                     "workspace {}".format(
                        missing_tool_count, workspace.name))


class EntityNotFound(Exception):
    def __init__(self, entity_id):
        super(EntityNotFound, self).__init__("Entity (%s) wasn't found" % entity_id)


class EntityMetadataImporter(object):

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        # entity, created = get_or_create(session, EntityMetadata, couchdb_id=document.get('_id'))
        # TODO migration: use inline metadata, not additional class
        return
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


def check_ip_address(ip_str):
    if not ip_str:
     return False
    if ip_str == '0.0.0.0':
        return False
    if ip_str == '0000:0000:0000:0000:0000:0000:0000:0000':
        return False
    try:
        IP(ip_str)
    except ValueError:
        return False
    return True


class HostImporter(object):
    """
        Class interface was removed in the new model.
        We will merge the interface data with the host.
        For ports we will create new services for open ports
        if it was not previously created.
    """

    def retrieve_ips_from_host_document(self, document):
        """

        :param document: json document from couchdb with host data
        :return: str with ip or name if no valid ip was found.
        """
        try:
            IP(document.get('name'))  # this will raise ValueError on invalid IPs
            yield document.get('name')
        except ValueError:
            host_ip = document.get('ipv4')
            created_ipv4 = False
            created_ipv6 = False
            if check_ip_address(host_ip):
                yield host_ip
                created_ipv4 = True
            host_ip = document.get('ipv6')
            if check_ip_address(host_ip):
                yield host_ip
            if not created_ipv4 or not created_ipv6:
                # sometimes the host lacks the ip.
                yield document.get('name')
            if created_ipv4 and created_ipv6:
                logger.warn('Two host will be created one with ipv4 and another one with ipv6. Couch id is {0}'.format(document.get('_id')))

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        hosts = []
        host_ips = [name_or_ip for name_or_ip in self.retrieve_ips_from_host_document(document)]
        interfaces = get_children_from_couch(workspace, document.get('_id'), 'Interface')
        command = None
        try:
            command = session.query(Command).get(couchdb_relational_map[document['metadata']['command_id']][0])
        except (KeyError, IndexError):
            command = None

        for interface in interfaces:
            interface = interface['value']
            if check_ip_address(interface['ipv4']['address']):
                interface_ip = interface['ipv4']['address']
                host, created = get_or_create(session, Host, ip=interface_ip, workspace=workspace)
                session.flush()
                host.default_gateway_ip = interface['ipv4']['gateway']
                self.merge_with_host(host, interface, workspace)
                hosts.append((host, created))
            if check_ip_address(interface['ipv6']['address']):
                interface_ip = interface['ipv6']['address']
                host, created = get_or_create(session, Host, ip=interface_ip, workspace=workspace)
                session.flush()
                host.default_gateway_ip = interface['ipv6']['gateway']
                self.merge_with_host(host, interface, workspace)
                hosts.append((host, created))
        if not hosts:
            # if not host were created after inspecting interfaces
            # we create a host with "name" as ip to avoid losing hosts.
            # some hosts lacks of interface
            for name_or_ip in host_ips:
                host, created = get_or_create(session, Host, ip=name_or_ip, workspace=workspace)
                hosts.append((host, created))

        if len(hosts) > 1:
            logger.warning('Total hosts found {0} for couchdb id {1}'.format(len(hosts), document.get('_id')))

        for host, created in hosts:
            # we update or set other host attributes in this cycle
            # Ticket #3387: if the 'os' field is None, we default to 'unknown
            if command and created:
                session.flush()
                CommandObject.create(host, command)

            if not document.get('os'):
                document['os'] = 'unknown'

            default_gateway = document.get('default_gateway', None)

            host.description = document.get('description')
            host.os = document.get('os')
            host.default_gateway_ip = default_gateway and default_gateway[0]
            host.default_gateway_mac = default_gateway and default_gateway[1]
            host.owned = document.get('owned', False)
            host.workspace = workspace
            yield host

    def merge_with_host(self, host, interface, workspace):
        if interface['mac']:
            host.mac = interface['mac']
        if interface['owned']:
            host.owned = interface['owned']

        #host.default_gateway_mac
        if interface['network_segment']:
            host.net_segment = interface['network_segment']
        if interface['description']:
            if not host.description:
                host.description = ''
            host.description += '\n Interface data: {0}'.format(interface['description'])
        if type(interface['hostnames']) in (str, unicode):
            interface['hostnames'] = [interface['hostnames']]

        for hostname_str in interface['hostnames'] or []:
            if not hostname_str:
                # skip empty hostnames
                continue
            hostname, created = get_or_create(
                session,
                Hostname,
                name=hostname_str,
                host=host,
                workspace=workspace
            )
        host.owned = host.owned or interface['owned']
        return host


class ServiceImporter(object):
    DOC_TYPE = 'Service'

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        #  service was always below interface, not it's below host.
        command = None
        try:
            command = session.query(Command).get(couchdb_relational_map[document['metadata']['command_id']][0])
        except (KeyError, IndexError):
            command = None

        # This should be safe because _id is always present and split never
        # returns an empty list
        parent_id = (document.get('parent') or document.get('_id')).split('.')[0]

        for relational_parent_id in couchdb_relational_map[parent_id]:
            host, created = get_or_create(session, Host, id=relational_parent_id)
            if command and created:
                session.flush()
                CommandObject.create(host, command)
            ports = document.get('ports')
            if len(ports) > 1:
                logger.warn('More than one port found in services!')
            for port in ports:
                try:
                    port = int(port)
                except ValueError:
                    logger.warn('Port {} of service {} is not a valid '
                                'integer. Using port 65534'.format(repr(port)))
                    port = 65534
                if port > (2**31 - 1):
                    # Bigger than the maximum int supported by postgres
                    logger.warn('Port number {} too big for service {}. '
                                'Using port 65535'.format(
                            port, document['_id']
                    ))
                    port = 65535
                service, created = get_or_create(session,
                                                 Service,
                                                 protocol=document.get('protocol'),
                                                 port=port,
                                                 host=host)
                service.description = document.get('description')
                service.owned = document.get('owned', False)
                service.banner = document.get('banner')
                service.name = document.get('name')
                if not document.get('status'):
                    logger.warning('Service {0} with empty status. Using \'open\' as status'.format(document['_id']))
                    document['status'] = 'open'
                status_mapper = {
                    'open': 'open',
                    'opened': 'open',
                    'up': 'open',
                    'closed': 'closed',
                    'down': 'closed',
                    'filtered': 'filtered',
                    'open|filtered': 'filtered',
                    'unknown': 'closed',
                    '-': 'closed',
                    'running': 'open',
                }
                couchdb_status = document.get('status', 'open')
                if couchdb_status.lower() not in status_mapper:
                    logger.warn('Service with unknown status "{0}" found! Status will default to open. Host is {1}'.format(couchdb_status, host.ip))
                service.status = status_mapper.get(couchdb_status, 'open')
                service.version = document.get('version')
                service.workspace = workspace
                session.flush()
                if command and created:
                    CommandObject.create(service, command)

                yield service


def get_or_create_user(session, username):
    rng = SystemRandom()
    password =  "".join(
        [rng.choice(string.ascii_letters + string.digits) for _ in
            xrange(12)])
    creator, created = get_or_create(session, User, username=username)
    if created:
        creator.active = False
        creator.password = password
    session.add(creator) # remove me
    session.commit() # remove me
    return creator


class VulnerabilityImporter(object):
    DOC_TYPE = ['Vulnerability', 'VulnerabilityWeb']

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        command = None
        try:
            command = session.query(Command).get(couchdb_relational_map[document['metadata']['command_id']][0])
        except (KeyError, IndexError):
            command = None
        vulnerability = None
        couch_parent_id = document.get('parent', None)
        if not couch_parent_id:
            couch_parent_id = '.'.join(document['_id'].split('.')[:-1])
        parent_ids = couchdb_relational_map[couch_parent_id]
        mapped_severity = MAPPED_VULN_SEVERITY
        try:
            severity = mapped_severity[document.get('severity')]
        except KeyError:
            logger.warn("Unknown severity value '%s' of vuln with id %s. "
                        "Using 'unclassified'",
                        document.get('severity'), document['_id'])
            severity = 'unclassified'
        for parent_id in parent_ids:
            if level == 2:
                parent = session.query(Host).filter_by(id=parent_id).first()
            if level == 4:
                parent = session.query(Service).filter_by(id=parent_id).first()
            owner_name = document.get('owner', None)
            creator = get_or_create_user(session, owner_name)
            if document['type'] == 'VulnerabilityWeb':
                method = document.get('method')
                path = document.get('path')
                pname = document.get('pname')
                website = document.get('website')
                vulnerability, created = get_or_create(
                    session,
                    VulnerabilityWeb,
                    name=document.get('name'),
                    description=document.get('desc').strip().strip('\n'),
                    service_id=parent.id,
                    method=method or '',
                    parameter_name=pname or '',
                    path=path or '',
                    website=website or '',
                    workspace=workspace,
                )

            if document['type'] == 'Vulnerability':
                vuln_params = {
                    'name': document.get('name'),
                    'workspace': workspace,
                    'description': document.get('desc').strip().strip('\n'),
                }
                if type(parent) == Host:
                    vuln_params.update({'host_id': parent.id})
                elif type(parent) == Service:
                    vuln_params.update({'service_id': parent.id})
                vulnerability, created = get_or_create(
                    session,
                    Vulnerability,
                    **vuln_params
                )
            vulnerability.severity = severity
            vulnerability.creator = creator
            vulnerability.confirmed = document.get('confirmed', False) or False
            vulnerability.data = document.get('data')
            vulnerability.ease_of_resolution = document.get('easeofresolution') if document.get('easeofresolution') else None
            vulnerability.resolution = document.get('resolution')

            vulnerability.owned = document.get('owned', False)
            #vulnerability.attachments = json.dumps(document.get('_attachments', {}))
            vulnerability.impact_accountability = document.get('impact', {}).get('accountability') or False
            vulnerability.impact_availability = document.get('impact', {}).get('availability') or False
            vulnerability.impact_confidentiality = document.get('impact', {}).get('confidentiality') or False
            vulnerability.impact_integrity = document.get('impact', {}).get('integrity') or False
            session.flush()
            if command and created:
                CommandObject.create(vulnerability, command)
            if document['type'] == 'VulnerabilityWeb':
                vulnerability.query_string = document.get('query')
                vulnerability.request = document.get('request')
                vulnerability.response = document.get('response')

                params = document.get('params', u'')
                if isinstance(params, (list, tuple)):
                    vulnerability.parameters = (u' '.join(params)).strip()
                else:
                    vulnerability.parameters = params if params is not None else u''
            status_map = {
                'opened': 'open',
                'open': 'open',
                'closed': 'closed',
                're-opened': 're-opened',
                'risk-accepted': 'risk-accepted',
            }
            try:
                status = status_map[document.get('status', 'opened')]
            except KeyError:
                logger.warn('Could not map vulnerability status {0}'.format(document['status']))
                continue
            vulnerability.status = status

            vulnerability.reference_instances.update(
                self.add_references(document, vulnerability, workspace))
            vulnerability.policy_violation_instances.update(
                self.add_policy_violations(document, vulnerability, workspace))

            # need the vuln ID before creating Tags for it
            session.flush()
            tags = document.get('tags', [])
            if tags and len(tags):
                create_tags(tags, vulnerability.id, document['type'])

            self.add_attachments(document, vulnerability, workspace)


        yield vulnerability

    def add_attachments(self, document, vulnerability, workspace):
        attachments_data = document.get('_attachments') or {}
        for attachment_name, attachment_data in attachments_data.items():
            # http://localhost:5984/evidence/334389048b872a533002b34d73f8c29fd09efc50.c7b0f6cba2fae8e446b7ffedfdb18026bb9ba41d/forbidden.png
            attachment_url = "http://{username}:{password}@{hostname}:{port}/{path}".format(
                username=server.config.couchdb.user,
                password=server.config.couchdb.password,
                hostname=server.config.couchdb.host,
                port=server.config.couchdb.port,
                path='{0}/{1}/{2}'.format(
                    workspace.name,
                    document.get('_id'),
                    quote(attachment_name))
            )
            try:
                response = requests.get(attachment_url)
                response.raise_for_status()
            except HTTPError:
                logger.warn(
                    'Unable to fetch attachment {} from workspace '
                    '{}'.format(
                        attachment_name, workspace.name
                    )
                )
                logger.debug('Attachment URL: {}'.format(attachment_url))
                continue
            response.raw.decode_content = True
            attachment_file = NamedTemporaryFile()
            attachment_file.write(response.content)
            attachment_file.seek(0)
            session.commit()
            file, created = get_or_create(
                session,
                File,
                filename=attachment_name,
                object_id=vulnerability.id,
                object_type='vulnerability')
            file.content = attachment_file.read()

            attachment_file.close()

    def add_policy_violations(self, document, vulnerability, workspace):
        policy_violations = set()
        for policy_violation in document.get('policyviolations', []):
            if not policy_violation:
                continue
            pv, created = get_or_create(
                session,
                PolicyViolation,
                name=policy_violation,
                workspace=workspace
            )
            session.flush()
            if created and pv.name not in map(lambda pva: pva.name, policy_violations):
                policy_violations.add(pv)
        return policy_violations

    def add_references(self, document, vulnerability, workspace):
        references = set()
        for ref in document.get('refs', []):
            if not ref:
                continue
            reference, created = get_or_create(
                session,
                Reference,
                name=ref,
                workspace=workspace
            )
            session.flush()
            if created and reference not in map(lambda ref: ref.name, references):
                references.add(reference)
        return references


class CommandImporter(object):

    DOC_TYPE = 'CommandRunInformation'
    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        import_source = 'shell'
        if document.get('command', '').startswith('Import '):
            import_source = 'report'
            # Now that we have a field that distinguished between shell commands
            # and imported reports, it is no longer required to directly format
            # in hte command field
            document['command'] = document['command'][len('Import '):-1]

        start_date = datetime.datetime.fromtimestamp(document.get('itime'))

        command, instance = get_or_create(
            session,
            Command,
            command=document.get('command', None),
            start_date=start_date,
            workspace=workspace,

        )
        if document.get('duration'):
            command.end_date = start_date + datetime.timedelta(seconds=document.get('duration'))

        command.import_source = import_source
        command.command = document.get('command', None)
        command.ip = document.get('ip', None)
        command.hostname = document.get('hostname', None)
        command.params = document.get('params', None)
        command.user = document.get('user', None)
        command.tool = 'unknown'  # It will be updated later
        command.workspace = workspace

        yield command


class NoteImporter(object):

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        couch_parent_id = '.'.join(document['_id'].split('.')[:-1])
        parent_document = get_object_from_couchdb(couch_parent_id, workspace)
        comment, created = get_or_create(
            session,
            Comment,
            text='{0}\n{1}'.format(document.get('text', ''), document.get('description', '')),
            object_id=couchdb_relational_map[parent_document.get('_id')],
            object_type=parent_document['type'].lower(),
            workspace=workspace)
        yield comment


class CredentialImporter(object):

    DOC_TYPE = 'Cred'
    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        command = None
        try:
            command = session.query(Command).get(couchdb_relational_map[document['metadata']['command_id']][0])
        except (KeyError, IndexError):
            command = None
        parents = []
        if level == 2:
            parent_ids = couchdb_relational_map[document['_id'].split('.')[0]]
            parents = session.query(Host).filter(Host.id.in_(parent_ids)).all()
        if level == 4:
            parent_ids = couchdb_relational_map['.'.join(document['_id'].split('.')[:3])]
            parents = session.query(Service).filter(Service.id.in_(parent_ids)).all()
        if not parents:
            raise Exception('Missing host or service for credential {0}'.format(document['_id']))
        for parent in parents:
            service = None
            host = None
            if isinstance(parent, Host):
                host = parent
            if isinstance(parent, Service):
                service = parent
            credential, created = get_or_create(
                session,
                Credential,
                username=document.get('username'),
                password=document.get('password'),
                host=host,
                service=service,
                workspace=workspace,
            )
            credential.password = document.get('password', None)
            credential.owned = document.get('owned', False)
            credential.description = document.get('description', None)
            credential.name = document.get('name', None)
            credential.workspace = workspace
            if command and created:
                session.flush()
                CommandObject.create(credential, command)
            yield credential


class WorkspaceImporter(object):

    DOC_TYPE = 'Workspace'
    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        workspace.description = document.get('description')
        if document.get('duration') and document.get('duration')['start']:
            workspace.start_date = datetime.datetime.fromtimestamp(float(document.get('duration')['start'])/1000)
        if document.get('duration') and document.get('duration')['end']:
            workspace.end_date = datetime.datetime.fromtimestamp(float(document.get('duration')['end'])/1000)
        for scope in [x.strip() for x in document.get('scope', '').split('\n') if x.strip()]:
            scope_obj, created = get_or_create(session, Scope, name=scope, workspace=workspace)
            session.flush()  # This fixes integrity errors for duplicate scope elements
        users = document.get('users', [])
        if not users:
            workspace.public = True
        for username in users:
            user = session.query(User).filter_by(username=username).first()
            if user is None:
                logger.warn('User {} not found but it has permissions for '
                            'workspace {}. Ignoring'.format(username,
                                                            workspace.name))
                continue
            (perm, created) = get_or_create(session, WorkspacePermission,
                                            user=user, workspace=workspace)
        yield workspace


class MethodologyImporter(object):
    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        if document.get('group_type') == 'template':
            methodology, created = get_or_create(session, MethodologyTemplate, name=document.get('name'))
            yield methodology

        if document.get('group_type') == 'instance':
            methodology, created = get_or_create(session, Methodology, name=document.get('name'), workspace=workspace)
            yield methodology


class TaskImporter(object):

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        try:
            methodology_id = couchdb_relational_map[document.get('group_id')][0]
        except KeyError:
            logger.warn('Could not found methodology with id {0}'.format(document.get('group_id')))
            return []
        except IndexError:
            logger.warn('Could not find methodology {0} of task {1}'.format(document.get('group_id'), document.get('_id')))
            return []

        if len(couchdb_relational_map[document.get('group_id')]) > 1:
            logger.error('It was expected only one parent in methodology {0}'.format(document.get('_id')))

        methodology = session.query(Methodology).filter_by(id=methodology_id, workspace=workspace).first()
        task_class = Task
        if not methodology:
            methodology = session.query(MethodologyTemplate).filter_by(id=methodology_id).first()
            task_class = TaskTemplate

        if task_class == TaskTemplate:
            task, task_created = get_or_create(session, task_class, name=document.get('name'))
            task.template = methodology
        else:
            task, task_created = get_or_create(session, task_class, name=document.get('name'), workspace=workspace)
            task.methodology = methodology

        task.description = document.get('description')

        assigned_users = []

        for username in document.get('assigned_to', []):
            if username:
                user = session.query(User).filter_by(username=username).first()
                if user:
                    assigned_users.append(user)

        task.assigned_to = assigned_users

        mapped_status = {
            'New': 'new',
            'In Progress': 'in progress',
            'Review': 'review',
            'Completed': 'completed'
        }
        task.status = mapped_status[document.get('status')]

        # we need the ID of the Task in order to add tags to it
        session.commit()
        tags = document.get('tags', [])
        if len(tags):
            create_tags(tags, task.id, 'task')
        #task.due_date = datetime.datetime.fromtimestamp(document.get('due_date'))
        return [task]



class ReportsImporter(object):

    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        report, created = get_or_create(session, ExecutiveReport, name=document.get('name'))
        report.template_name = document.get('template_name', 'generic_default.docx')
        report.title = document.get('title')
        report.status = document.get('status')
        # TODO: add tags
        report.conclusions = document.get('conclusions')
        report.confirmed = document.get('confirmed', False)
        report.summary = document.get('summary')
        report.recommendations = document.get('recommendations')
        report.enterprise = document.get('enterprise')
        report.summary = document.get('summary')
        report.scope = document.get('scope')
        report.objectives = document.get('objectives')
        report.grouped = document.get('grouped', False)
        report.workspace = workspace
        try:
            report.vuln_count = document['totalVulns']['total']
        except KeyError:
            logger.warning("Couldn't load vuln count of report".format(document.get('_id')))
        if document.get('owner'):
            report.creator = get_or_create_user(session, document.get('owner'))
        session.flush()
        old_attachments = session.query(File).filter_by(
            object_id=report.id,
            object_type='vulnerability',
        )
        for old_attachment in old_attachments:
            db.session.delete(old_attachment)
        for filename, attachment in document.get('_attachments', {}).items():
            attachment_url = "http://{username}:{password}@{hostname}:{port}/{path}".format(
                username=server.config.couchdb.user,
                password=server.config.couchdb.password,
                hostname=server.config.couchdb.host,
                port=server.config.couchdb.port,
                path='{0}/{1}/{2}'.format(workspace.name, document.get('_id'),
                                          filename)
            )
            response = requests.get(attachment_url)
            response.raw.decode_content = True
            faraday_file = response.content
            file, created = get_or_create(
                session,
                File,
                object_id=report.id,
                object_type='executive_report',
                name=os.path.splitext(os.path.basename(filename))[0],
                filename=os.path.basename(filename),
            )
            file.content=faraday_file
        yield report


class CommunicationImporter(object):
    def update_from_document(self, document, workspace, level=None, couchdb_relational_map=None):
        comment, created = get_or_create(
            session,
            Comment,
            text=document.get('text'),
            object_id=workspace.id,
            object_type='workspace',
            workspace=workspace)
        yield comment


class FaradayEntityImporter(object):
    # Document Types: [u'Service', u'Communication', u'Vulnerability', u'CommandRunInformation', u'Reports', u'Host', u'Workspace']

    def __init__(self, workspace_name):
        self.workspace_name = workspace_name

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
        logger.debug('Getting class importer for {0} in workspace {1}'.format(doc_type, self.workspace_name))
        importer_class_mapper = {
            'EntityMetadata': EntityMetadataImporter,
            'Host': HostImporter,
            'Service': ServiceImporter,
            'Note': NoteImporter,
            'Credential': CredentialImporter,
            'CommandRunInformation': CommandImporter,
            'Workspace': WorkspaceImporter,
            'Vulnerability': VulnerabilityImporter,
            'VulnerabilityWeb': VulnerabilityImporter,
            'TaskGroup': MethodologyImporter,
            'Task': TaskImporter,
            'Reports': ReportsImporter,
            'Communication': CommunicationImporter
        }
        importer_self = importer_class_mapper.get(doc_type, None)
        if not importer_self:
            raise NotImplementedError('Class importer for {0} not implemented'.format(doc_type))
        return importer_self


class ImportCouchDBUsers():

    def modular_crypt_pbkdf2_sha1(self, checksum, salt, iterations=1000):
        return '$pbkdf2${iterations}${salt}${checksum}'.format(
            iterations=iterations,
            salt=ab64_encode(salt),
            checksum=ab64_encode(unhexlify(checksum)),
        )

    def convert_couchdb_hash(self, original_hash):
        if not original_hash.startswith(COUCHDB_PASSWORD_PREFIX):
            # Should be a plaintext password
            return original_hash
        checksum, salt, iterations = original_hash[
            len(COUCHDB_PASSWORD_PREFIX):].split(',')
        iterations = int(iterations)
        return self.modular_crypt_pbkdf2_sha1(checksum, salt, iterations)

    def get_hash_from_document(self, doc):
        scheme = doc.get('password_scheme', 'unset')
        if scheme != 'pbkdf2':
            # Flask Security will encrypt the password next time the user logs in.
            logger.warning('Found user {0} without password. Setting its '
                           'password to "changeme"'.format(doc.get('name')))
            return 'changeme'
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
            logger.debug('Creating user {0}'.format(username))
            admin = db.session.query(User).filter_by(username=username).first()
            if not admin:
                app.user_datastore.create_user(
                    username=username,
                    email=username + '@test.com',
                    password=self.convert_couchdb_hash(password),
                    is_ldap=False,
                    role='admin'
                )
            else:
                admin.password=self.convert_couchdb_hash(password)

    def import_users(self, all_users, admins):
        # Import non admin users
        if 'error' in all_users:
            raise Exception(all_users['reason'])
        for user in all_users['rows']:
            user = user['doc']
            if not user['_id'].startswith(COUCHDB_USER_PREFIX):
                # It can be a view or something other than a user
                continue
            if user['name'] in admins.keys():
                # This is an already imported admin user, skip
                continue
            try:
                role = user['roles'][0]
            except (KeyError, IndexError):
                role = 'client'
            else:
                if role not in ['admin', 'client', 'pentester']:
                    logger.warn(
                        "Invalid role for user {}: {}".format(user['name'],
                                                              role)
                    )
                    role = 'client'
            logger.debug(u'Importing user {0}'.format(user['name']))
            old_user = db.session.query(User).filter_by(username=user['name']).first()
            if not old_user:
                app.user_datastore.create_user(
                    username=user['name'],
                    email=user['name'] + '@test.com',
                    password=self.get_hash_from_document(user),
                    is_ldap=False,
                    role=role,
                )
            else:
                old_user.password = self.get_hash_from_document(user)

    def run(self):
        all_users, admins = self.get_users_and_admins()
        self.import_users(all_users, admins)
        self.import_admins(admins)
        db.session.commit()



class ImportVulnerabilityTemplates():

    def __init__(self):
        self.names = Counter()

    def run(self):
        logger.debug("Importing vulnerability templates")
        cwe_url = "http://{username}:{password}@{hostname}:{port}/{path}".format(
            username=server.config.couchdb.user,
            password=server.config.couchdb.password,
            hostname=server.config.couchdb.host,
            port=server.config.couchdb.port,
            path='cwe/_all_docs?include_docs=true'
        )

        try:
            cwes = requests.get(cwe_url)
            cwes.raise_for_status()
        except HTTPError:
            logger.warn('Unable to retrieve Vulnerability Templates Database. Moving on.')
            return
        except RequestException as e:
            logger.exception(e)
            return

        for cwe in (cwes.json()['rows']):
            document = cwe['doc']
            new_severity = self.get_severity(document)

            new_name = self.get_name(document)

            vuln_template, created = get_or_create(session,
                                                   VulnerabilityTemplate,
                                                   name=new_name)

            vuln_template.description = document.get('description')
            vuln_template.resolution = document.get('resolution')
            vuln_template.severity = new_severity

            if isinstance(document.get('references'), list):
                references = document.get('references')
            elif isinstance(document.get('references'), (str, unicode)):
                references = [x.strip()
                              for x in document.get('references').split(',')
                              if x.strip()]
            else:
                logger.warn("Unknown type of vuln template references: {}. "
                            "Reference data: {}".format(
                                type(document.get('references')),
                                document))
                continue
            cwe_field = document.get('cwe')
            if cwe_field not in references:
                references.append(cwe_field)
            for ref_doc in references:
                vuln_template.references.add(ref_doc)



    def get_name(self, document):
        doc_name = document.get('name')
        count = self.names[doc_name]

        if count > 0:
            name = u'{0} ({1})'.format(doc_name, count)
        else:
            name = doc_name

        self.names[doc_name] += 1

        return name

    def get_severity(self, document):
        default = 'unclassified'

        mapped_exploitation = MAPPED_VULN_SEVERITY

        for key in mapped_exploitation.keys():
            if key in document.get('exploitation','').lower():
                return mapped_exploitation[key]

        logger.warn(
            'Vuln template exploitation \'{0}\' not found. Using \'{1}\' instead.'.format(document.get('exploitation'), default)
        )

        return default

class ImportLicense():

    def run(self):
        licenses_url = "http://{username}:{password}@{hostname}:{port}/{path}".format(
            username=server.config.couchdb.user,
            password=server.config.couchdb.password,
            hostname=server.config.couchdb.host,
            port=server.config.couchdb.port,
            path='faraday_licenses/_all_docs?include_docs=true'
        )

        try:
            licenses = requests.get(licenses_url)
            licenses.raise_for_status()
        except HTTPError:
            logger.warn('Unable to retrieve Licenses Database. Moving on.')
            return
        except RequestException as e:
            logger.exception(e)
            return

        for license in licenses.json()['rows']:
            document = license['doc']

            license_obj, created = get_or_create(session,
                                                   License,
                                                   product=document.get('product'),
                                                   start_date=datetime.datetime.strptime(document['start'], "%Y-%m-%dT%H:%M:%S.%fZ"),
                                                   end_date=datetime.datetime.strptime(document['end'], "%Y-%m-%dT%H:%M:%S.%fZ"),
            )
            license_obj.notes=document.get('notes')
            license_obj.type=document.get('lictype')

class ImportCouchDB():
    def _open_couchdb_conn(self):

        self.couch_url = "http://{username}:{password}@{hostname}:{port}".format(
                username=server.config.couchdb.user,
                password=server.config.couchdb.password,
                hostname=server.config.couchdb.host,
                port=server.config.couchdb.port,
        )

        try:
            workspaces_list = requests.get('{0}/_all_dbs'.format(self.couch_url)).json()
        except Exception as ex:
            print(ex)
            sys.exit(1)

        return workspaces_list

    def has_access_to(self, workspace_name):
        response = requests.get('{0}/{1}/_security'.format(self.couch_url, workspace_name))
        if response.status_code == 401:
            return False
        return True

    def run(self):
        """
            Main entry point for couchdb import
        """
        workspaces_list = self._open_couchdb_conn()
        license_import = ImportLicense()
        license_import.run()
        vuln_templates_import = ImportVulnerabilityTemplates()
        vuln_templates_import.run()
        users_import = ImportCouchDBUsers()
        users_import.run()

        logger.info('Importing workspaces. Using {0} threads'.format(multiprocessing.cpu_count() * 2))
        for workspace_name in workspaces_list:
            logger.debug(u'Setting up workspace {}'.format(workspace_name))

            if not self.has_access_to(workspace_name):
                logger.error(u"Unauthorized access to CouchDB. Make sure faraday-server's"\
                             " configuration file has CouchDB admin's credentials set")
                sys.exit(1)
            self.import_workspace_into_database(workspace_name)

    def get_objs(self, host, obj_type, level, workspace):
        if obj_type == 'Credential':
            obj_type = 'Cred'
        data = {
            "map": "function(doc) { if(doc.type == '%s' && doc._id.split('.').length == %d && !doc._deleted) emit(null, doc); }" % (obj_type, level)
        }

        documents = requests.post(host, json=data).json()
        return documents

    def verify_host_vulns_count_is_correct(self, couchdb_relational_map, couchdb_relational_map_by_type, workspace):
        hosts = session.query(Host).filter_by(workspace=workspace)
        logger.info('Verifying data migration')
        for host in tqdm(hosts, total=hosts.count()):
            parent_couchdb_id = None
            for couchdb_id, relational_ids in couchdb_relational_map_by_type.items():
                for obj_data in relational_ids:
                    if obj_data['type'] == 'Host' and host.id == obj_data['id']:
                        parent_couchdb_id = couchdb_id
                        break
                if parent_couchdb_id:
                    break
            if not parent_couchdb_id:
                logger.warn('Could not found couchdb id! This is fine if you created hosts after migration')
                continue
            vulns = get_children_from_couch(workspace, parent_couchdb_id, 'Vulnerability')
            interfaces = get_children_from_couch(workspace, parent_couchdb_id, 'Interface')
            for interface in interfaces:
                interface = interface['value']
                vulns += get_children_from_couch(workspace, interface.get('_id'), 'Vulnerability')

            old_host_count = len(set(map(lambda vuln: vuln['value'].get('name'), vulns)))
            new_host_count = len(set(map(lambda vuln: vuln.name, host.vulnerabilities)))
            if old_host_count != new_host_count:
                logger.info("Host count didn't match")
                if old_host_count < new_host_count:
                    logger.warn('More host were found in postgreSQL. This is normal if you used the workspace {0}'.format(workspace.id))
                if new_host_count < old_host_count:
                    logger.error('Some hosts were not imported!!')

    def verify_import_data(self, couchdb_relational_map, couchdb_relational_map_by_type, workspace):
        self.verify_host_vulns_count_is_correct(couchdb_relational_map, couchdb_relational_map_by_type, workspace)
        all_docs_url = "http://{username}:{password}@{hostname}:{port}/{workspace_name}/_all_docs?include_docs=true".format(
                    username=server.config.couchdb.user,
                    password=server.config.couchdb.password,
                    hostname=server.config.couchdb.host,
                    port=server.config.couchdb.port,
                    workspace_name=workspace.name
        )
        all_ids = map(lambda x: x['doc']['_id'], requests.get(all_docs_url).json()['rows'])
        if len(all_ids) != len(couchdb_relational_map.keys()):
            missing_objs_filename = os.path.join(os.path.expanduser('~/.faraday'), 'logs', 'import_missing_objects_{0}.json'.format(workspace.name))
            missing_ids = set(all_ids) - set(couchdb_relational_map.keys())
            missing_ids = set([x for x in missing_ids if not re.match(r'^\_design', x)])
            objs_diff = []
            if missing_ids:
                logger.debug('Downloading missing couchdb docs')
            for missing_id in (missing_ids):
                not_imported_obj = get_object_from_couchdb(missing_id, workspace)

                if not_imported_obj.get('type', None) == 'Interface':
                    # we know that interface obj was not imported
                    continue
                filter_keys = ['views', 'validate_doc_update']
                if not any(map(lambda x: x not in filter_keys, not_imported_obj.keys())):
                    # we filter custom views, validation funcs, etc
                    logger.warning(
                        'Not all objects were imported. Saving difference to file {0}'.format(missing_objs_filename))
                    objs_diff.append(not_imported_obj)

                    with open(missing_objs_filename, 'w') as missing_objs_file:
                        missing_objs_file.write(json.dumps(objs_diff))

    def import_level_objects(self, couch_url, faraday_importer, couchdb_relational_map_by_type, couchdb_relational_map, command_tool_map, level, obj_type, workspace):
        obj_importer = faraday_importer.get_importer_from_document(obj_type)()
        objs_dict = self.get_objs(couch_url, obj_type, level, workspace)
        print('Importing {0} from workspace {1}'.format(obj_type, workspace.name))
        for raw_obj in tqdm(objs_dict.get('rows', [])):
            # we use no_autoflush since some queries triggers flush and some relationship are missing in the middle
            with session.no_autoflush:
                raw_obj = raw_obj['value']
                couchdb_id = raw_obj['_id']

                # first let's make sure no invalid chars are present in the Raw objects
                raw_obj = invalid_chars.clean_dict(raw_obj)

                for new_obj in obj_importer.update_from_document(raw_obj, workspace, level, couchdb_relational_map):
                    if not new_obj:
                        continue
                    set_metadata(raw_obj, new_obj)
                    map_tool_with_command_id(command_tool_map,
                                             raw_obj)
                    session.commit()
                    couchdb_relational_map_by_type[couchdb_id].append({'type': obj_type, 'id': new_obj.id})
                    couchdb_relational_map[couchdb_id].append(new_obj.id)

    def import_workspace_into_database(self, workspace_name):
        with app.app_context():

            faraday_importer = FaradayEntityImporter(workspace_name)
            workspace, created = get_or_create(session, Workspace, name=workspace_name)
            session.commit()

            couch_url = "http://{username}:{password}@{hostname}:{port}/{workspace_name}/_temp_view?include_docs=true".format(
                username=server.config.couchdb.user,
                password=server.config.couchdb.password,
                hostname=server.config.couchdb.host,
                port=server.config.couchdb.port,
                workspace_name=workspace_name
            )

            # obj_types are tuples. the first value is the level on the tree
            # for the desired obj.
            obj_types = OBJ_TYPES
            couchdb_relational_map = defaultdict(list)
            couchdb_relational_map_by_type = defaultdict(list)
            command_tool_map = {}
            for level, obj_type in obj_types:
                try:
                    self.import_level_objects(
                        couch_url,
                        faraday_importer,
                        couchdb_relational_map_by_type,
                        couchdb_relational_map,
                        command_tool_map,
                        level,
                        obj_type,
                        workspace
                    )
                except Exception as ex:
                    logger.exception(ex)
                    continue
            update_command_tools(workspace, command_tool_map,
                                 couchdb_relational_map_by_type)
            session.commit()
            self.verify_import_data(couchdb_relational_map, couchdb_relational_map_by_type, workspace)

            session.expunge_all()
            session.close()
            return created
