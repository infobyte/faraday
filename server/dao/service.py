# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from sqlalchemy.sql import func
from sqlalchemy.orm.query import Bundle
from server.dao.base import FaradayDAO
from server.models import Host, Interface, Service, EntityMetadata


class ServiceDAO(FaradayDAO):
    MAPPED_ENTITY = Service
    COLUMNS_MAP = {
        "name": Service.name,
        "protocol": Service.protocol,
        "version": Service.version,
        "status": Service.status,
        "owned": Service.owned
    }

    def list(self, port=None):
        return self.__get_services_by_host(port)

    def get_services_by_parent(self, parent):
        interface_bundle = Bundle('service',
                Service.id, Service.name, Service.description, Service.protocol,
                Service.status, Service.ports, Service.version, Service.owned,
                EntityMetadata.couchdb_id, EntityMetadata.revision)

        query = self._session.query(interface_bundle).\
                outerjoin(EntityMetadata, EntityMetadata.id == Interface.entity_metadata_id)\
                .filter(Interface.id == parent)
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
                'protocol': service.protocol,
                'status': service.status,
                'ports': service.ports,
                'version': service.version,
                'owned': service.owned}
            }



    def __get_services_by_host(self, port=None):
        result = self._session.query(Host.name,
                                     Host.os,
                                     Interface.ipv4_address,
                                     Interface.ipv6_address,
                                     Service.name,
                                     Service.ports).join(Host.interfaces, Interface.services).all()

        hosts = {}
        for service in result:
            service_ports = map(int, service[5].split(','))
            if port is not None and port not in service_ports:
                continue

            host = hosts.get(service[0], None)
            if not host:
                hosts[service[0]] = {
                    'name': service[0],
                    'os': service[1],
                    'ipv4': service[2],
                    'ipv6': service[3],
                    'services': [] }
                host = hosts[service[0]]

            host['services'].append({ 'name': service[4], 'ports': service_ports })

        return hosts.values()

    def count(self, group_by=None):
        total_count = self._session.query(func.count(Service.id)).scalar()

        # Return total amount of services if no group-by field was provided
        if group_by is None:
            return { 'total_count': total_count }

        # Otherwise return the amount of services grouped by the field specified
        if group_by not in ServiceDAO.COLUMNS_MAP:
            return None

        col = ServiceDAO.COLUMNS_MAP.get(group_by)
        query = self._session.query(col, func.count())\
                             .filter(Service.status.in_(('open', 'running')))\
                             .group_by(col)

        res = query.all()

        return { 'total_count': total_count,
                 'groups': [ { group_by: value, 'count': count } for value, count in res ] }


