# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os
import re
import atexit
import server.models
import server.config
import server.couchdb
import server.importer
import server.utils.logger

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm.exc import MultipleResultsFound

logger = server.utils.logger.get_logger(__name__)


_db_manager = None

def initialize():
    global _db_manager
    _db_manager = Manager()

def is_valid_workspace(workspace_name):
    return _db_manager.is_valid_workspace(workspace_name)

def get(workspace_name):
    return _db_manager.get_workspace(workspace_name)

def teardown_context():
    """ This is called by Flask to cleanup sessions created in the context of a request """
    _db_manager.close_sessions()

def get_manager():
    return _db_manager


class Manager(object):
    def __init__(self):
        self.__workspaces = {}

        # Open all existent databases on workspaces path
        self.__init_sessions()

        # Register database closing to be executed when process goes down
        atexit.register(self.close_databases)

    def __init_sessions(self):
        # Only loads does databases that are already created and
        # are present on the current CouchDB instance
        databases = self.__list_databases().intersection(self.__list_workspaces())

        for database_name in databases:
            self.__init_workspace(database_name)

    def __list_databases(self):
        def is_a_valid_database(filename):
            return is_a_file(filename) and is_a_valid_name(filename)
        def is_a_file(filename):
            return os.path.isfile(os.path.join(server.config.FARADAY_SERVER_DBS_DIR, filename))
        def is_a_valid_name(filename):
            return bool(re.match('^[a-z][a-z0-9_$()+/-]*\\.db$', filename))

        # List all valid databases stored on configured directory
        db_filenames = filter(is_a_valid_database, os.listdir(server.config.FARADAY_SERVER_DBS_DIR))

        # Remove extensions and move on
        return set([os.path.splitext(filename)[0] for filename in db_filenames])

    def __list_workspaces(self):
        couchdb_server_conn = server.couchdb.CouchDBServer()
        return set(couchdb_server_conn.list_workspaces())

    def __init_workspace(self, ws_name, db_conn=None):
        if ws_name not in self.__workspaces:
            new_workspace = Workspace(ws_name, db_conn=db_conn)
            self.__workspaces[ws_name] = new_workspace

    def get_workspace(self, ws_name):
        try:
            return self.__workspaces[ws_name]
        except KeyError:
            raise WorkspaceNotFound(ws_name)

    def create_workspace(self, workspace):
        # create the couch database first
        ok = server.couchdb.create_workspace(workspace)
        if ok:
            self.__process_new_workspace(workspace.get('name'))
        return ok

    def update_workspace(self, workspace):
        # update the couch database
        return server.couchdb.update_workspace(workspace)

    def delete_workspace(self, ws_name):
        # create the couch database first
        ok = server.couchdb.delete_workspace(ws_name)
        if ok:
            self.__process_delete_workspace(ws_name)
        return ok

    def __process_new_workspace(self, ws_name):
        if ws_name in self.__workspaces:
            logger.info(u"Workspace {} already exists. Ignoring change.".format(ws_name))
        elif not server.couchdb.server_has_access_to(ws_name):
            logger.error(u"Unauthorized access to CouchDB for Workspace {}. Make sure faraday-server's"\
                         " configuration file has CouchDB admin's credentials set".format(ws_name))
        else:
            self.__create_and_import_workspace(ws_name)

    def __create_and_import_workspace(self, ws_name):
        new_db_conn = Connector(ws_name)

        if new_db_conn.exists():
            # TODO(mrocha): if somehow this happens, then we should check for integrity and reimport
            # if necessary. After that we should add it into the databases dict
            logger.warning(u"Workspace {} already exists but wasn't registered at startup".format(ws_name))
        else:
            server.importer.import_workspace_into_database(ws_name, new_db_conn)

        self.__init_workspace(ws_name, db_conn=new_db_conn)

    def __process_delete_workspace(self, ws_name):
        if ws_name not in self.__workspaces:
            logger.info(u"Workspace {} doesn't exist. Ignoring change.".format(ws_name))
        else:
            logger.info(u"Deleting workspace {} from Faraday Server".format(ws_name))
            self.__delete_workspace(ws_name)

    def __delete_workspace(self, ws_name):
        self.get_workspace(ws_name).delete()
        del self.__workspaces[ws_name]

    def is_valid_workspace(self, ws_name):
        return ws_name in self.__workspaces

    def __contains__(self, ws_name):
        return self.is_valid_workspace(ws_name)

    def close_sessions(self):
        for workspace in self.__workspaces.values():
            workspace.close_session()

    def close_databases(self):
        for workspace in self.__workspaces.values():
            workspace.close()


class Workspace(object):
    def __init__(self, db_name, db_conn=None, couchdb_conn=None, couchdb_server_conn=None):
        self.__db_conn = db_conn or Connector(db_name)
        self.__couchdb_conn = couchdb_conn or server.couchdb.Workspace(db_name, couchdb_server_conn)

    @property
    def connector(self):
        return self.__db_conn

    @property
    def session(self):
        # TODO(mrocha): should we check if session is None here???
        return self.__db_conn.session

    @property
    def couchdb(self):
        return self.__couchdb_conn

    def close_session(self):
        self.__db_conn.close()

    def close(self):
        self.close_session()

    def delete(self):
        self.close()
        self.__db_conn.delete()


class Connector(object):
    def __init__(self, db_name):
        self.db_name = db_name

        self.__db_path = self.__get_db_path()
        self.__db_conf = Configuration(self)
        self.__setup_engine()

        # From here it is now ready to open, or create/open
        if self.exists():
            self.session = self.__open_session()
        else:
            self.session = None

    def __get_db_path(self):
        return os.path.join(server.config.FARADAY_SERVER_DBS_DIR, '%s.db' % self.db_name)

    def __setup_engine(self):
        self.__engine = create_engine('sqlite:///%s' % self.__db_path) # XXX: is this safe?
        # TODO(mrocha): review this piece of code. i'm not sure what this implicates
        # when having multiple databases open using the same model
        server.models.Base.metadata.bind = self.__engine

    def __open_session(self):
        return scoped_session(sessionmaker(autocommit=False,
                                           autoflush=False,
                                           bind=self.__engine))

    def create(self):
        if self.exists():
            raise RuntimeError("Cannot create new database. Database {} already exists".format(self.db_name))

        server.models.Base.metadata.create_all(self.__engine)
        self.session = self.__open_session()
        self.__db_conf.setup_new_database()

    def exists(self):
        return os.path.exists(self.__db_path)

    def close(self):
        # TODO(mrocha): Detail how this works
        if self.session is not None:
            self.session.remove()

    def delete(self):
        self.close()
        os.remove(self.__db_path)

    def is_integrous(self):
        if not self.__db_conf.was_migration_successful():
            logger.info(u"Workspace {} wasn't migrated successfully".format(self.db_name))
            return False

        elif self.__db_conf.get_schema_version() != server.models.SCHEMA_VERSION:
            logger.info(u"Workspace {} has an old schema version ({} != {})".format(
                self.db_name, self.__db_conf.get_schema_version(), server.models.SCHEMA_VERSION))
            return False

        return True

class DocumentImporter(object):
    def __init__(self, db_conn, post_processing_change_cbk=None):
        self.__db_conn = db_conn
        self.__db_conf = Configuration(db_conn)
        self.__post_processing_change_cbk = post_processing_change_cbk

    def add_entity_from_doc(self, document):
        """
        ISSUES:
            * Other entities related to this new document may be not already
            include into the database (ie: these documents are added on future
            changes)
        """
        entity = server.models.FaradayEntity.parse(document)
        if entity is None:
            return False

        entity.add_relationships_from_db(self.__db_conn.session)
        self.__db_conn.session.add(entity)

        try:
            self.__db_conn.session.commit()
            logger.info(u'New {} ({}) was added in Workspace {}'.format(
                entity.entity_metadata.document_type,
                getattr(entity, 'name', '<no-name>'),
                self.__db_conn.db_name))

        except IntegrityError, e:
            # For now, we silently rollback because it is an excepted
            # scenario when we create documents from the server and its
            # change notification arrives
            self.__db_conn.session.rollback()
            return False

        return True

    def delete_entity_from_doc_id(self, document_id):
        """
        ISSUES:
            * Delete child entities. Have not found cases where this is a problem. So far,
            clients are deleting all CouchDBs documents properly, and if they don't, the
            DBs still are consistent. Maybe use SQLAlchemy's cascades if this become a
            problem. Status: Somewhat OK

            * Doc ID maps to multiple elements. This could happen since the ID is a hash
            based in a few entity's properties which can be replicated. Status: TODO
        """
        entity = self.__get_modified_entity(document_id)
        if entity is not None:
            self.__db_conn.session.delete(entity)
            self.__db_conn.session.commit()
            logger.info(u'A {} ({}) was deleted in Workspace {}'.format(
                entity.entity_metadata.document_type,
                getattr(entity, 'name', '<no-name>'),
                self.__db_conn.db_name))
            return True

        logger.debug(u'Document ({}) was not present in database to delete'.format(document_id))
        return False

    def update_entity_from_doc(self, document):
        """
        ISSUES:
            * Updated relationships are not taken into account. Status: TODO
        """
        entity = self.__get_modified_entity(document.get('_id'))
        if entity is not None:
            entity.update_from_document(document)
            entity.entity_metadata.update_from_document(document)
            self.__db_conn.session.commit()
            logger.info(u'A {} ({}) was updated in Workspace {}'.format(
                entity.entity_metadata.document_type,
                getattr(entity, 'name', '<no-name>'),
                self.__db_conn.db_name))
            return True

        logger.debug(u'Document ({}) was not present in database to update'.format(document.get('_id')))
        return False

    def __get_modified_entity(self, document_id):
        metadata = self.get_document_metadata(document_id)
        if metadata is None:
            logger.info(u'Doc {} was not found in the database'.format(document_id))
            return None

        # Obtain the proper table on which to perform the entity operation
        entity_cls = server.models.FaradayEntity.get_entity_class_from_type(
            metadata.document_type)

        # TODO(mrocha): Add error handling here when no or more than one entities where found.
        entity = self.__db_conn.session.query(entity_cls)\
                               .join(server.models.EntityMetadata)\
                               .filter(server.models.EntityMetadata.couchdb_id == document_id)\
                               .one()
        return entity

    def get_document_metadata(self, document_id):
        metadata = None
        try:
            metadata = self.__db_conn.session.query(server.models.EntityMetadata)\
                                             .filter(server.models.EntityMetadata.couchdb_id == document_id)\
                                             .one_or_none()
        except MultipleResultsFound:
            logger.warning(u'Multiple entities were found for doc {}.'\
                'Ignoring change'.format(document_id))
        return metadata


class Configuration(object):
    # TODO(mrocha): use enums in database metadata table
    # instead of constants defined here
    LAST_SEQ_CONFIG = 'last_seq'
    MIGRATION_SUCCESS = 'migration'
    SCHEMA_VERSION = 'version'

    def __init__(self, db_conn):
        self.__db_conn = db_conn

    def setup_new_database(self, from_seq=0):
        self.set_last_seq(from_seq)
        self.set_migration_status(False)
        self.set_schema_version()

    def get_last_seq(self):
        config = self.__get_config(Configuration.LAST_SEQ_CONFIG)
        if config is not None:
            return int(config.value)
        else:
            return 0

    def set_last_seq(self, last_seq):
        self.__set_config(Configuration.LAST_SEQ_CONFIG, last_seq)


    def was_migration_successful(self):
        config = self.__get_config(Configuration.MIGRATION_SUCCESS)
        return (config is not None and config.value == 'true')

    def get_schema_version(self):
        config = self.__get_config(Configuration.SCHEMA_VERSION)
        return (config.value if config is not None else None)

    def set_migration_status(self, was_successful):
        self.__set_config(Configuration.MIGRATION_SUCCESS, 'true' if was_successful else 'false')

    def set_schema_version(self):
        self.__set_config(Configuration.SCHEMA_VERSION, server.models.SCHEMA_VERSION)

    def __get_config(self, option):
        try:
            result = self.__db_conn.session\
                        .query(server.models.DatabaseMetadata)\
                        .filter(server.models.DatabaseMetadata.option == option)\
                        .one_or_none()

        except MultipleResultsFound:
            msg = u'Database {} should not have the option {} defined multiple times'.format(self.__db_conn.db_name, option)
            logger.error(msg)
            raise RuntimeError(msg)

        return result

    def __set_config(self, option, value):
        config = self.__get_config(option)
        if config is None:
            config = server.models.DatabaseMetadata(option=option)
        config.value = value

        self.__db_conn.session.merge(config)
        self.__db_conn.session.commit()


#
# Profile queries performance on debug mode
# Debug utility extracted from http://docs.sqlalchemy.org/en/latest/faq/performance.html
#
if server.config.is_debug_mode():
    from sqlalchemy import event
    from sqlalchemy.engine import Engine
    import time

    @event.listens_for(Engine, "before_cursor_execute")
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        context._query_start_time = time.time()
        logger.debug(u"Start Query:\n{}".format(statement))
        logger.debug(u"Parameters:\n{!r}".format(parameters))

    @event.listens_for(Engine, "after_cursor_execute")
    def after_cursor_execute(conn, cursor, statement,
        parameters, context, executemany):
        total = time.time() - context._query_start_time
        logger.debug(u"Query Complete. Total Time: {:.02f}ms".format(total*1000))


#
# Exception definitions
#
class WorkspaceNotFound(Exception):
    def __init__(self, workspace_name):
        super(WorkspaceNotFound, self).__init__('Workspace "%s" not found' % workspace_name)

