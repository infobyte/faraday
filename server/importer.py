# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import sys
import server.utils.logger
import server.couchdb
import server.database
import server.models
from restkit.errors import RequestError, Unauthorized

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

def import_workspace_into_database(workspace_name, db_conn=None, couchdb_conn=None, couchdb_server_conn=None):
    db_conn = db_conn or server.database.Connector(workspace_name)
    couchdb_conn = couchdb_conn or server.couchdb.Workspace(workspace_name, couchdb_server_conn)

    # If database doesn't exist. Create and import workspace
    if not db_conn.exists():
        import_on_new_database(db_conn, couchdb_conn)

    # Database exists. Check if it is corrupt to reimport
    elif not db_conn.is_integrous():
        reimport_on_database(db_conn, couchdb_conn)

    return db_conn

def import_on_new_database(db_conn, couchdb_conn):
    if db_conn.exists():
        raise RuntimeError('Database {} already exists'.format(db_conn.db_name))

    logger.info(u'Creating database for workspace {}'.format(db_conn.db_name))
    _create_and_import_db(db_conn, couchdb_conn)

def reimport_on_database(db_conn, couchdb_conn):
    """ WARNING: Make sure to do all necessary verifications on
    the database you are working on. If the database exists then
    it will truncate and lose all data previously stored there"""
    if not db_conn.exists():
        raise RuntimeError('Database {} does not exist'.format(db_conn.db_name))

    logger.info(u'Importing workspace {} again'.format(db_conn.db_name))
    _truncate_and_import_db(db_conn, couchdb_conn)

def _create_and_import_db(db_conn, couchdb_conn):
    db_conn.create()
    db_conf = server.database.Configuration(db_conn)
    db_conf.set_last_seq(couchdb_conn.get_last_seq())

    try:
        _import_from_couchdb(db_conn, couchdb_conn)
    except Exception, e:
        import traceback
        logger.debug(traceback.format_exc())
        logger.error(u'Error while importing workspace {}: {!s}'.format(db_conn.db_name, e))
        db_conn.delete()
        raise e

    # Reaching this far without errors means a successful migration
    db_conf.set_migration_status(True)

def _truncate_and_import_db(db_conn, couchdb_conn):
    db_conn.delete()

    db_conn = server.database.Connector(db_conn.db_name)
    _create_and_import_db(db_conn, couchdb_conn)

def _import_from_couchdb(db_conn, couchdb_conn):
    total_amount = couchdb_conn.get_total_amount_of_documents()
    processed_docs, progress = 0, 0
    should_flush_changes = False
    host_entities = {}

    def flush_changes():
        host_entities.clear()
        db_conn.session.commit()
        db_conn.session.expunge_all()

    for doc in couchdb_conn.get_documents(per_request=1000):
        processed_docs = processed_docs + 1
        current_progress = (processed_docs * 100) / total_amount
        if current_progress > progress:
            _show_progress(u'  * Importing {} from CouchDB'.format(db_conn.db_name), progress)
            progress = current_progress
            should_flush_changes = True

        entity = server.models.FaradayEntity.parse(doc.get('doc'))
        if entity is not None:
            if isinstance(entity, server.models.Host) and should_flush_changes:
                flush_changes()
                should_flush_changes = False

            try:
                entity.add_relationships_from_dict(host_entities)
            except server.models.EntityNotFound as e:
                logger.warning(u"Ignoring {} entity ({}) because its parent wasn't found".format(
                    entity.entity_metadata.document_type, entity.entity_metadata.couchdb_id))
            else:
                host_entities[doc.get('key')] = entity
                db_conn.session.add(entity)

    logger.info(u'{} importation done!'.format(db_conn.db_name))
    flush_changes()

def _show_progress(msg, percentage):
    try:
        sys.stdout.write('{}: {}%\r'.format(msg, percentage))
        sys.stdout.flush()
    except IOError:
        logger.warning("Unable to write progress to stdout")
