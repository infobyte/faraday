# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os, sys
import atexit
import logging
import threading
import server.models
import server.config
import server.couchdb
import server.utils.logger

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm.exc import MultipleResultsFound


logger = server.utils.logger.get_logger(__name__)
workspace = {}

"""

from sqlalchemy import event
from sqlalchemy.engine import Engine
import time

@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    context._query_start_time = time.time()
    logger.debug("Start Query:\n%s" % statement)
    logger.debug("Parameters:\n%r" % (parameters,))

@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, 
    parameters, context, executemany):
    total = time.time() - context._query_start_time
    logger.debug("Query Complete!")
    logger.debug("Total Time: %.02fms" % (total*1000))
"""


class WorkspaceDatabase(object):
    LAST_SEQ_CONFIG = 'last_seq'
    MIGRATION_SUCCESS = 'migration'
    SCHEMA_VERSION = 'version'

    def __init__(self, name):
        self.__workspace = name

        self.database = Database(self.__workspace)
        self.couchdb = server.couchdb.Workspace(self.__workspace)

        self.__setup_database_synchronization()
        self.__open_or_create_database()
        self.__start_database_synchronization()

    def __open_or_create_database(self):
        if not self.database.exists():
            self.create_database()
        else:
            self.database.open_session()
            self.check_database_integrity()

    def check_database_integrity(self):
        if not self.was_migration_successful():
            logger.info("Workspace %s wasn't migrated successfully. Trying again..." % self.__workspace)
            self.remigrate_database()
        elif self.get_schema_version() != server.models.SCHEMA_VERSION:
            logger.info("Workspace %s has an old schema version (%s != %s). Remigrating workspace..." % (self.__workspace, self.get_schema_version(), server.models.SCHEMA_VERSION))
            self.remigrate_database()

    def remigrate_database(self):
            self.database.close()
            self.database.delete()
            self.database = Database(self.__workspace)

            self.create_database()
    
    def create_database(self):
        logger.info('Creating database for workspace %s' % self.__workspace)
        self.database.create()
        self.database.open_session()

        try:
            self.set_last_seq(self.couchdb.get_last_seq())
            self.set_migration_status(False)
            self.set_schema_version()

            self.import_from_couchdb()

            self.set_migration_status(True)

        except Exception, e:
            import traceback
            traceback.print_exc()
            logger.error('Error while importing workspace {}: {}'.format(self.__workspace, str(e)))
            self.delete()
            raise e

    
    def import_from_couchdb(self):
        total_amount = self.couchdb.get_total_amount_of_documents()
        processed_docs, progress = 0, 0
        should_flush_changes = False
        host_entities = {}

        def flush_changes():
            host_entities.clear()
            self.database.session.commit()
            self.database.session.expunge_all()

        for doc in self.couchdb.get_documents(per_request=1000):
            processed_docs = processed_docs + 1
            current_progress = (processed_docs * 100) / total_amount 
            if current_progress > progress:
                self.__show_progress('Importing', progress)
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
                    logger.warning("Ignoring %s entity (%s) because its parent wasn't found" %
                        (entity.entity_metadata.document_type, entity.entity_metadata.couchdb_id))
                else:
                    host_entities[doc.get('key')] = entity
                    self.database.session.add(entity)

        flush_changes()

    def __show_progress(self, msg, percentage):
        sys.stdout.write('{}: {}%\r'.format(msg, percentage))
        sys.stdout.flush()

    def __setup_database_synchronization(self):
        self.__sync_seq_milestone = 0

        # As far as we know, before the changes monitor is
        # launched the data is synchronized with CouchDB
        self.__data_sync_lock = threading.Lock()
        self.__data_sync_event = threading.Event()
        self.__data_sync_event.set()

    def __start_database_synchronization(self):
        self.__last_seq = self.get_last_seq()
        logger.debug('Workspace %s last update: %s' % (self.__workspace, self.__last_seq))
        # Start changes monitor thread
        self.couchdb.start_changes_monitor(self.__process_change, last_seq=self.__last_seq)

    # CHA, CHA, CHA, CHANGESSSS
    def __process_change(self, change):
        logger.debug('New change for %s: %s' % (self.__workspace, change.change_doc))

        if change.deleted:
            logger.debug('Doc %s was deleted' % change.doc_id)
            self.__process_del(change)

        elif change.updated:
            logger.debug('Doc %s was updated' % change.doc_id)
            self.__process_update(change)

        elif change.added:
            logger.debug('Doc %s was added' % change.doc_id)
            self.__process_add(change)

        self.__update_last_seq(change)

    def __process_del(self, change):
        """
        ISSUES:
            * Delete child entities. Have not found cases where this is a problem. So far,
            clients are deleting all CouchDBs documents properly, and if they don't, the
            DBs still are consistent. Maybe use SQLAlchemy's cascades if this become a
            problem. Status: Somewhat OK

            * Doc ID maps to multiple elements. This could happen since the ID is a hash
            based in a few entity's properties which can be replicated. Status: TODO
        """
        entity = self.__get_modified_entity(change)
        if entity is not None:
            logger.info(u'A {} ({}) will be deleted'.format(entity.DOC_TYPE, entity.name))
            self.database.session.delete(entity)
            self.database.session.commit()

    def __process_update(self, change):
        """
        ISSUES:
            * Updated relationships are not taken into account. Status: TODO
        """
        entity = self.__get_modified_entity(change)
        if entity is not None:
            logger.info(u'A {} ({}) will be updated'.format(entity.DOC_TYPE, entity.name))
            entity.update_from_document(change.doc)
            entity.entity_metadata.update_from_document(change.doc)
            self.database.session.commit()

    def __get_modified_entity(self, change):
        metadata = self.database.session.query(server.models.EntityMetadata)\
            .filter(server.models.EntityMetadata.couchdb_id == change.doc_id)\
            .one_or_none()

        if metadata is not None:
            # Obtain the proper table on which to perform the entity operation
            entity_cls = server.models.FaradayEntity.get_entity_class_from_type(
                metadata.document_type)
            
            entity = self.database.session.query(entity_cls)\
                .join(server.models.EntityMetadata)\
                .filter(server.models.EntityMetadata.couchdb_id == change.doc_id)\
                .one()

            return entity

        else:
            logger.info('Doc {} was not found in the database'.format(change.doc_id))
            return None

    def __process_add(self, change):
        """
        ISSUES:
            * Other entities related to this new document may be not already
            include into the database (ie: these documents are added on future
            changes)
        """
        entity = server.models.FaradayEntity.parse(change.doc)
        if entity is not None:
            logger.info(u'New {} ({}) will be added'.format(entity.DOC_TYPE, entity.name))
            entity.add_relationships_from_db(self.database.session)
            self.database.session.add(entity)
            self.database.session.commit()

    def get_last_seq(self):
        config = self.get_config(WorkspaceDatabase.LAST_SEQ_CONFIG)
        if config is None:
            return 0

        last_seq = int(config.value)
        return last_seq

    def was_migration_successful(self):
        config = self.get_config(WorkspaceDatabase.MIGRATION_SUCCESS)
        return (config is not None and config.value == 'true')

    def get_schema_version(self):
        config = self.get_config(WorkspaceDatabase.SCHEMA_VERSION)
        return config.value if config is not None else None

    def get_config(self, option):
        query = self.database.session.query(server.models.DatabaseMetadata)
        query = query.filter(server.models.DatabaseMetadata.option == option)

        try:
            result = query.one_or_none()
        except MultipleResultsFound:
            raise Exception('Database Inconsistency: Should not have the option %s defined multiple times' % option)

        return result

    def set_last_seq(self, last_seq):
        self.set_config(WorkspaceDatabase.LAST_SEQ_CONFIG, last_seq)
        self.__last_seq = last_seq
        # Set sync event when the database is updated relative
        # to the milestone set
        if self.__last_seq >= self.__sync_seq_milestone:
            self.__data_sync_event.set()

    def set_migration_status(self, was_successful):
        self.set_config(WorkspaceDatabase.MIGRATION_SUCCESS, 'true' if was_successful else 'false')

    def set_schema_version(self):
        self.set_config(WorkspaceDatabase.SCHEMA_VERSION, server.models.SCHEMA_VERSION)

    def set_config(self, option, value):
        config = self.get_config(option)
        if config is None:
            config = server.models.DatabaseMetadata(option=option)
        config.value = value

        self.database.session.merge(config)
        self.database.session.commit()

    def __update_last_seq(self, change):
        if change.seq is not None:
            self.set_last_seq(change.seq)

    def close(self):
        self.database.close()

    def delete(self):
        self.database.close()
        self.database.delete()

    def wait_until_sync(self, timeout):
        """
        Wait a maximum of <timeout> seconds for Faraday server to
        synchronize its database with CouchDB. This is intended to
        provide a solution to data inconsistencies between CouchDB
        and the server on short windows of time between an update
        and its importation into Faraday server's database.
        Currently, this case is commonly seen when entities are
        updated or added and, immediately afterwards, a query for
        them is made.
        """
        # Synchronize access to data synchronization to avoid race
        # conditions on heavy workload (mainly because multiple
        # threads could set different milestones and clear the sync
        # event on unexpected moments, rendering the possibility that
        # this function returns False when data is in fact synchronized
        # or to wait <timeout> seconds without need). (PS: maybe this
        # not necessary given its current use and cause overhead for a
        # situation that may not be troublesome)
        # This may cause performance issues if processing CouchDB
        # changes is taking a lot of time. If that is a persistent
        # issue adjust the timeout to a lower value to minimize its
        # impact
        with self.__data_sync_lock:
            self.__wait_until_database_is_sync(timeout)

    def __wait_until_database_is_sync(self, timeout):
        """
        This function will establish a milestone by asking CouchDB's last
        update sequence number to then wait for an event signal from the
        changes monitor when its last procesed change is newer or as new
        as this milestone.
        If synchronization isn't achieved in <timeout> seconds it will
        return False, communicating that data consistency can be ensured
        after this call.
        """
        self.__set_sync_milestone()

        logger.debug("Waiting until synchronization with CouchDB (ws: %d, couchdb: %d)" %\
            (self.__last_seq, self.__sync_seq_milestone))

        self.__data_sync_event.wait(timeout)
        is_sync = self.__data_sync_event.is_set()

        if is_sync:
            logger.debug("Synchronized with CouchDB to seq %d" % self.__last_seq)
        else:
            logger.debug("Synchronization timed out. Working with outdated database")

        return is_sync

    def __set_sync_milestone(self):
        """
        Set a milestone from where we can check if data is synchronized
        between the server and CouchDB
        """
        self.__sync_seq_milestone = self.couchdb.get_last_seq()
        # Clear event if last database seq version is outdated
        # relative to CouchDB
        if self.__last_seq < self.__sync_seq_milestone:
            self.__data_sync_event.clear()

class Database(object):
    def __init__(self, db_name):
        self.__db_path = os.path.join(server.config.FARADAY_BASE, 'server/workspaces/%s.db' % db_name)
        self.__engine = create_engine('sqlite:///%s' % self.__db_path) # XXX: Is this safe?
        server.models.Base.metadata.bind = self.__engine

    def create(self):
        server.models.Base.metadata.create_all(self.__engine)

    def open_session(self):
        self.session = scoped_session(sessionmaker(autocommit=False,
                                                   autoflush=False,
                                                   bind=self.__engine))

    def exists(self):
        return os.path.exists(self.__db_path)

    def close(self):
        pass

    def delete(self):
        os.remove(self.__db_path)

    def teardown_context(self):
        self.session.remove()

def setup():
    setup_workspaces()
    server.couchdb.start_dbs_monitor(process_db_change)

def setup_workspaces():
    couchdb = server.couchdb.CouchDBServer()

    for ws in couchdb.list_workspaces():
        setup_workspace(ws)

    atexit.register(server.database.close_databases)

def setup_workspace(ws_name):
    logger.info('Setting up workspace %s' % ws_name)
    workspace[ws_name] = WorkspaceDatabase(ws_name)

def close_databases():
    for ws in workspace.values():
        ws.close()

def process_db_change(change):
    if change.created:
        logger.info('Workspace %s was created' % change.db_name)
        process_new_workspace(change.db_name)
    elif change.deleted:
        logger.info('Workspace %s was deleted' % change.db_name)
        process_delete_workspace(change.db_name)

def process_new_workspace(ws_name):
    if ws_name in workspace:
        logger.info("Workspace %s was already migrated. Ignoring change." % ws_name)
    else:
        setup_workspace(ws_name)

def process_delete_workspace(ws_name):
    if ws_name not in workspace:
        logger.info("Workspace %s wasn't migrated at startup. Ignoring change." % ws_name)
    else:
        logger.info("Deleting workspace %s from Faraday Server" % ws_name)
        delete_workspace(ws_name)

def delete_workspace(ws_name):
    get(ws_name).delete()
    del workspace[ws_name]
 
def teardown_context():
    """ This is called by Flask to cleanup sessions created in the context of a request """
    for ws in workspace.values():
        ws.database.teardown_context()

class WorkspaceNotFound(Exception):
    def __init__(self, workspace_name):
        super(WorkspaceNotFound, self).__init__('Workspace "%s" not found' % workspace_name)

def is_valid_workspace(workspace_name):
    return workspace_name in workspace

def get(ws_name):
    try:
        return workspace[ws_name]
    except KeyError:
        raise WorkspaceNotFound(ws_name)

