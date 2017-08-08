# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from sqlalchemy.orm.query import Bundle

from server.dao.base import FaradayDAO
from server.models import Command, EntityMetadata
from server.utils.database import apply_search_filter, paginate

class CommandDAO(FaradayDAO):
    MAPPED_ENTITY = Command
    COLUMNS_MAP = {
        'couchid': [EntityMetadata.couchdb_id]
    }
    STRICT_FILTERING = ["couchid"]

    def list(self, search=None, page=0, page_size=0, command_filter={}):
        results = self.__query_database(search, page, page_size, command_filter)

        rows = [ self.__get_command_data(result.command) for result in results ]

        result = {
            'commands': rows
        }

        return result

    def __query_database(self, search=None, page=0, page_size=0, command_filter={}):
        command_bundle = Bundle('command',
                                Command.itime,
                                Command.ip,
                                Command.hostname,
                                Command.command,
                                Command.user,
                                Command.workspace_id,
                                Command.duration,
                                Command.params,
                                EntityMetadata.couchdb_id)

        query = self._session.query(command_bundle)\
                             .outerjoin(EntityMetadata, EntityMetadata.id == Command.entity_metadata_id)

        # Apply filtering options to the query
        query = apply_search_filter(query, self.COLUMNS_MAP, None, command_filter, self.STRICT_FILTERING)

        if page_size:
            query = paginate(query, page, page_size)

        results = query.all()

        return results

    def __get_command_data(self, command):
        return {
            'id': command.couchdb_id,
            'key': command.couchdb_id,
            'value': {
                "_id": command.couchdb_id,
                "itime": command.itime,
                "ip": command.ip,
                "hostname": command.hostname,
                "command": command.command,
                "user": command.user,
                "workspace": command.workspace,
                "duration": command.duration,
                "params": command.params}}
