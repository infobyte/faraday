# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from sqlalchemy import distinct
from sqlalchemy.sql import func
from sqlalchemy.orm.query import Bundle

from server.dao.base import FaradayDAO
from server.models import Host, Interface, Service, EntityMetadata, Vulnerability
from server.utils.database import apply_search_filter

class ServiceDAO(FaradayDAO):
    MAPPED_ENTITY = Service
    COLUMNS_MAP = {
        "interface":    [Service.interface_id],
        "couchid":      [EntityMetadata.couchdb_id],
        'id':           [Service.id],
        "name":         [Service.name],
        "protocol":     [Service.protocol],
        "version":      [Service.version],
        "status":       [Service.status],
        "owned":        [Service.owned],
        "hostid":       [Host.id]
    }
    STRICT_FILTERING = ["couchid", "interface", 'id', 'hostid']

    def list(self, service_filter={}):
        service_bundle = Bundle('service',
                Service.id, Service.name, Service.description, Service.protocol,
                Service.status, Service.ports, Service.version, Service.owned,
                Service.interface_id,
                func.count(distinct(Vulnerability.id)).label('vuln_count'), EntityMetadata.couchdb_id,\
                EntityMetadata.revision, EntityMetadata.update_time, EntityMetadata.update_user,\
                EntityMetadata.update_action, EntityMetadata.creator, EntityMetadata.create_time,\
                EntityMetadata.update_controller_action, EntityMetadata.owner)

        query = self._session.query(service_bundle).\
                group_by(Service.id).\
                outerjoin(EntityMetadata, EntityMetadata.id == Service.entity_metadata_id).\
                outerjoin(Vulnerability, Service.id == Vulnerability.service_id).group_by(Service.id).\
                outerjoin(Interface, Interface.id == Service.interface_id).\
                outerjoin(Host, Host.id == Interface.host_id)

        query = apply_search_filter(query, self.COLUMNS_MAP, None, service_filter, self.STRICT_FILTERING)

        raw_services = query.all()
        services = [self.__get_service_data(r.service) for r in raw_services]
        result = {'services': services}
        return result

    def __get_service_data(self, service):
        return {
            'id': service.couchdb_id,
            'key': service.couchdb_id,
            '_id': service.id,
            'value': {
                '_id': service.couchdb_id,
                '_rev': service.revision,
                'name': service.name,
                'description': service.description,
                'metadata': {
                    'update_time': service.update_time,
                    'update_user': service.update_user,
                    'update_action': service.update_action,
                    'creator': service.creator,
                    'create_time': service.create_time,
                    'update_controller_action': service.update_controller_action,
                    'owner': service.owner
                },
                'protocol': service.protocol,
                'status': service.status,
                'ports':  [ int(i) for i in service.ports.split(',') if service.ports],
                'version': service.version,
                'owned': service.owned,
                'owner': service.owner
                },
            'vulns': service.vuln_count,
            }

    def count(self, group_by=None):
        total_count = self._session.query(func.count(Service.id)).scalar()

        # Return total amount of services if no group-by field was provided
        if group_by is None:
            return { 'total_count': total_count }

        # Otherwise return the amount of services grouped by the field specified
        if group_by not in ServiceDAO.COLUMNS_MAP:
            return None

        col = ServiceDAO.COLUMNS_MAP.get(group_by)[0]
        query = self._session.query(col, func.count())\
                             .filter(Service.status.in_(('open', 'running')))\
                             .group_by(col)

        res = query.all()

        return { 'total_count': total_count,
                 'groups': [ { group_by: value, 'count': count } for value, count in res ] }


