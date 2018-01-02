# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import server.models
import server.config
import server.couchdb
import server.utils.logger

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import MultipleResultsFound

logger = server.utils.logger.get_logger(__name__)


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
        entity = server.models.FaradayEntity.parse(self.__db_conn.session, document)
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


#
# Connection to a database common to all workspaces
#

def setup_common(db_path='sqlite:////tmp/test.db'):
    common_engine = create_engine(db_path)
    common_session = scoped_session(sessionmaker(autocommit=False,
                                                autoflush=False,
                                                bind=common_engine))
    server.models.CommonBase.metadata.bind = common_engine
    from server.models import CommonBase
    CommonBase.metadata.create_all(bind=common_engine)
    CommonBase.query = common_session.query_property()
    return common_session
