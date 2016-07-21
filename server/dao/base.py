# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import server.database
import server.utils.logger

from server.models import EntityMetadata


class FaradayDAO(object):
    MAPPED_ENTITY = None
    COLUMNS_MAP = {}

    def __init__(self, workspace):
        self._logger = server.utils.logger.get_logger(__name__)
        try:
            self._session = server.database.get(workspace).database.session
        except KeyError:
            raise WorkspaceNotFound(workspace)

    def get_all(self):
        self.__check_valid_operation()
        return self._session.query(self.MAPPED_ENTITY).all()

    def __check_valid_operation(self):
        if self.MAPPED_ENTITY is None:
            raise Exception('Invalid operation')

    def get_by_couchdb_id(self, couchdb_id):
        self.__check_valid_operation()
        query = self._session.query(self.MAPPED_ENTITY)\
            .join(EntityMetadata)\
            .filter(EntityMetadata.couchdb_id == couchdb_id)
        return query.one()

    def save(self, obj):
        self._session.add(obj)
        self._session.commit()

