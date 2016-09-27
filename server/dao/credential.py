# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from sqlalchemy.orm.query import Bundle

from server.dao.base import FaradayDAO
from server.models import Credential, EntityMetadata
from server.utils.database import apply_search_filter

class CredentialDAO(FaradayDAO):

    MAPPED_ENTITY = Credential

    COLUMNS_MAP = {
        'couchid':          [EntityMetadata.couchdb_id],
        'username':         [Credential.username],
        'password':         [Credential.password],
    }

    STRICT_FILTERING = ["couchid"] 

    def list(self, search=None, cred_filter={}):
        results = self.__query_database(search, cred_filter)

        rows = [ self.__get_cred_data(result.cred) for result in results ]

        result = {
            'rows': rows
        }

        return result

    def __query_database(self, search=None, cred_filter={}):
        creds_bundle = Bundle('cred', Credential.username, Credential.password, Credential.name,
                Credential.description, Credential.owned, EntityMetadata.couchdb_id,\
                EntityMetadata.revision, EntityMetadata.update_time, EntityMetadata.update_user,\
                EntityMetadata.update_action, EntityMetadata.creator, EntityMetadata.create_time,\
                EntityMetadata.update_controller_action, EntityMetadata.owner)

        query = self._session.query(creds_bundle)\
                             .outerjoin(EntityMetadata, EntityMetadata.id == Credential.entity_metadata_id)

        # Apply filtering options to the query
        query = apply_search_filter(query, self.COLUMNS_MAP, search, cred_filter, self.STRICT_FILTERING)

        results = query.all()
        return results

    def __get_cred_data(self, cred):
        return {
            'id': cred.couchdb_id,
            'key': cred.couchdb_id,
            'value': {
                '_id': cred.couchdb_id,
                'username': cred.username,
                'password': cred.password,
                'owner': cred.owner,
                'owned': cred.owned,
                'description': cred.description,
                'name': cred.name,
                'metadata': {
                    'update_time': cred.update_time,
                    'update_user': cred.update_user,
                    'update_action': cred.update_action,
                    'creator': cred.creator,
                    'create_time': cred.create_time,
                    'update_controller_action': cred.update_controller_action,
                    'owner': cred.owner
                },
                'couchid': cred.couchdb_id }}

