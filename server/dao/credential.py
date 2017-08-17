# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from sqlalchemy.orm.query import Bundle
from sqlalchemy import not_

from server.dao.base import FaradayDAO
from server.models import Credential, EntityMetadata
from server.utils.database import apply_search_filter


class CredentialDAO(FaradayDAO):

    MAPPED_ENTITY = Credential

    COLUMNS_MAP = {
        'couchid': [EntityMetadata.couchdb_id],
        'username': [Credential.username],
        'password': [Credential.password],
        'service_id': [],
        'host_id': []}

    STRICT_FILTERING = ["couchid"]

    def list(self, search=None, cred_filter={}):
        results = self.__query_database(search, cred_filter)

        rows = [self.__get_cred_data(result.cred) for result in results]
        result = {
            'rows': rows
        }

        return result

    def __query_database(self, search=None, cred_filter={}):
        creds_bundle = Bundle(
                'cred', Credential.username, Credential.password,
                Credential.name, EntityMetadata.couchdb_id,
                Credential.description, Credential.owned,
                EntityMetadata.revision, EntityMetadata.update_time,
                EntityMetadata.update_user, EntityMetadata.create_time,
                EntityMetadata.update_action, EntityMetadata.creator,
                EntityMetadata.update_controller_action, EntityMetadata.owner,
                EntityMetadata.command_id)

        query = self._session.query(creds_bundle)\
                             .outerjoin(EntityMetadata, EntityMetadata.id == Credential.entity_metadata_id)

        query = query.filter(Credential.workspace == self.workspace)
        # Apply filtering options to the query
        query = apply_search_filter(query, self.COLUMNS_MAP, search, cred_filter, self.STRICT_FILTERING)

        # I apply a custom filter for search by hostId and serviceId.
        # 'LIKE' for search by serviceId.%, that return only credentials started with serviceId.
        if cred_filter.get('service_id') is not None:
            query = query.filter(EntityMetadata.couchdb_id.like(cred_filter.get('service_id') + ".%"))

        # 'LIKE' for search by hostId.%, with that LIKE we receive credentials of services also.
        # I need another like for filter credentials of services (%.%.%)
        if cred_filter.get('host_id') is not None:
            query = query.filter(
                EntityMetadata.couchdb_id.like(cred_filter.get('host_id') + ".%")).filter(
                    not_(EntityMetadata.couchdb_id.like("%.%.%")))

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
                    'owner': cred.owner,
                    'command_id': cred.command_id
                },
                'couchid': cred.couchdb_id}}
