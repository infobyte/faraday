# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import sys
import server.utils.logger
import server.couchdb
import server.database
import server.models
from server.utils.database import get_or_create
from server.database import session
from restkit.errors import RequestError, Unauthorized

from tqdm import tqdm

logger = server.utils.logger.get_logger(__name__)


def import_workspaces():
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
        _import_from_couchdb(workspace, couchdb_conn)
        session.commit()
    except Exception as ex:
        logger.exception(ex)
        session.rollback()
        raise ex

    return created


def _import_from_couchdb(workspace, couchdb_conn):
    total_amount = couchdb_conn.get_total_amount_of_documents()
    processed_docs, progress = 0, 0
    should_flush_changes = False
    host_entities = {}

    def flush_changes():
        host_entities.clear()
        session.commit()
        session.expunge_all()

    for doc in tqdm(couchdb_conn.get_documents(per_request=1000), total=total_amount):
        processed_docs = processed_docs + 1
        current_progress = (processed_docs * 100) / total_amount
        if current_progress > progress:
            _show_progress(u'  * Importing {} from CouchDB'.format(workspace.name), progress)
            progress = current_progress
            should_flush_changes = True

        entity = server.models.FaradayEntity.parse(doc.get('doc'))
        if entity is not None:
            if isinstance(entity, server.models.Host) and should_flush_changes:
                flush_changes()
                should_flush_changes = False

            try:
                entity.add_relationships_from_dict(host_entities)
            except server.models.EntityNotFound:
                logger.warning(u"Ignoring {} entity ({}) because its parent wasn't found".format(
                    entity.entity_metadata.document_type, entity.entity_metadata.couchdb_id))
            else:
                host_entities[doc.get('key')] = entity
                session.add(entity)

    logger.info(u'{} importation done!'.format(workspace.name))
    flush_changes()


def _show_progress(msg, percentage):
    sys.stdout.write('{}: {}%\r'.format(msg, percentage))
    sys.stdout.flush()
