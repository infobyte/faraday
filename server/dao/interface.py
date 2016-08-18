# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from server.dao.base import FaradayDAO
from server.models import Interface, EntityMetadata
from sqlalchemy.orm.query import Bundle

class InterfaceDAO(FaradayDAO):
    MAPPED_ENTITY = Interface

    def count(self):
        total_count = self._session.query(func.count(Interface.id)).scalar()
        return { 'total_count': total_count }

    def list(self, host_id):
        interface_bundle = Bundle('interface',
                Interface.id, Interface.name, Interface.description, Interface.mac,
                Interface.owned, Interface.hostnames, Interface.network_segment, Interface.ipv4_address,
                Interface.ipv4_gateway, Interface.ipv4_dns, Interface.ipv4_mask, Interface.ipv6_address,
                Interface.ipv6_gateway, Interface.ipv6_dns, Interface.ipv6_prefix, Interface.ports_filtered,
                Interface.ports_opened, Interface.ports_closed, Interface.host_id, EntityMetadata.couchdb_id,
                EntityMetadata.revision)

        query = self._session.query(interface_bundle).\
                outerjoin(EntityMetadata, EntityMetadata.id == Interface.entity_metadata_id)\
                .filter(Interface.host_id == host_id)
        raw_interfaces = query.all()
        interfaces = [self.__get_interface_data(r.interface) for r in raw_interfaces]
        result = {'interfaces': interfaces}
        return result

    def __get_interface_data(self, interface):
        return {
            'id': interface.couchdb_id,
            'key': interface.couchdb_id,
            '_id': interface.id,
            'value': {
                '_id': interface.couchdb_id,
                '_rev': interface.revision,
                'name': interface.name,
                'description': interface.description,
                'mac': interface.mac,
                'owned': interface.owned,
                'hostnames': interface.hostnames,
                'network_segment': interface.network_segment,
                'ipv4': {'address': interface.ipv4_address,
                         'gateway': interface.ipv4_gateway,
                         'dns': interface.ipv4_dns,
                         'mask': interface.ipv4_mask},
                'ipv6': {'address': interface.ipv6_address,
                         'gateway': interface.ipv6_gateway,
                         'dns': interface.ipv6_dns,
                         'prefix': interface.ipv6_prefix},
                'ports': {'filtered': interface.ports_filtered,
                          'opened': interface.ports_opened,
                          'closed': interface.ports_closed},
                'host_id': interface.host_id}
            }
