# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os, sys
import atexit
import logging
import server.models
import server.config
import server.couchdb
import server.utils.logger

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm.exc import MultipleResultsFound


logger = server.utils.logger.get_logger(__name__)
workspace = {}

class WorkspaceDatabase(object):
    LAST_SEQ_CONFIG = 'last_seq'

    def __init__(self, name):
        self.__workspace = name
        self.database = Database(self.__workspace)
        self.couchdb = server.couchdb.Workspace(self.__workspace)

        self.__open_or_create_database()

        logger.debug('Workspace %s last update: %s' % (self.__workspace, self.get_last_seq()))
        self.couchdb.start_changes_monitor(self.__process_change, last_seq=self.get_last_seq())

    def __open_or_create_database(self):
        """
        TODO: ADD DATABASE INTEGRITY PROPERTY ON CREATIION
        """
        if not self.database.exists():
            logger.info('Creating database for workspace %s' % self.__workspace)
            self.database.create()
            self.database.open_session()

            try:
                self.set_last_seq(self.couchdb.get_last_seq())
                self.import_from_couchdb()
            except Exception, e:
                import traceback
                traceback.print_exc()
                logger.error('Error while importing workspace {}: {}'.format(self.__workspace, str(e)))
                self.database.delete()
                raise e

        else:
            self.database.open_session()
    
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

                host_entities[doc.get('key')] = entity
                entity.add_relationships_from_dict(host_entities)
                self.database.session.add(entity)

        flush_changes()

    def __show_progress(self, msg, percentage):
        sys.stdout.write('{}: {}%\r'.format(msg, percentage))
        sys.stdout.flush()

    # CHA, CHA, CHA, CHANGESSSS
    def __process_change(self, change):
        logger.debug('New change for %s: %s' % (self.__workspace, change.change_doc))
        self.__update_last_seq(change)

        if change.deleted:
            logger.debug('Doc %s was deleted' % change.doc_id)
            self.__process_del(change)

        elif change.updated:
            logger.debug('Doc %s was updated' % change.doc_id)
            self.__process_update(change)

        elif change.added:
            logger.debug('Doc %s was added' % change.doc_id)
            self.__process_add(change)

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
            logger.info('A {} ({}) will be deleted'.format(entity.DOC_TYPE, entity.name))
            self.database.session.delete(entity)
            self.database.session.commit()

    def __process_update(self, change):
        """
        ISSUES:
            * Updated relationships are not taken into account. Status: TODO
        """
        entity = self.__get_modified_entity(change)
        if entity is not None:
            logger.info('A {} ({}) will be updated'.format(entity.DOC_TYPE, entity.name))
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
            logger.info('New {} ({}) will be added'.format(entity.DOC_TYPE, entity.name))
            entity.add_relationships_from_db(self.database.session)
            self.database.session.add(entity)
            self.database.session.commit()

    def get_last_seq(self):
        config = self.get_config(WorkspaceDatabase.LAST_SEQ_CONFIG)
        if config is None:
            return 0

        last_seq = int(config.value)
        return last_seq

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
    couchdb = server.couchdb.CouchDBServer()
    for ws in couchdb.list_workspaces():
        logger.info('Setting up workspace %s' % ws)
        workspace[ws] = WorkspaceDatabase(ws)
    atexit.register(server.database.close_databases)

def teardown_context():
    """ This is called by Flask to cleanup sessions created in the context of a request """
    for ws in workspace.values():
        ws.database.teardown_context()

def close_databases():
    for ws in workspace.values():
        ws.close()
 
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

