# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from server.utils.database import apply_search_filter
from server.dao.base import FaradayDAO
from server.models import Interface, EntityMetadata
from sqlalchemy.orm.query import Bundle
from sqlalchemy.sql import func

class InterfaceDAO(FaradayDAO):
    MAPPED_ENTITY = Interface
    COLUMNS_MAP = {
        "host":    [Interface.host_id],
        "couchid": [EntityMetadata.couchdb_id],
    }
    STRICT_FILTERING = ["host", "couchid"]

    def count(self):
        total_count = self._session.query(func.count(Interface.id)).scalar()
        return { 'total_count': total_count }

    def list(self, interface_filter={}):
        interface_bundle = Bundle('interface',
                Interface.id, Interface.name, Interface.description, Interface.mac,
                Interface.owned, Interface.hostnames, Interface.network_segment, Interface.ipv4_address,
                Interface.ipv4_gateway, Interface.ipv4_dns, Interface.ipv4_mask, Interface.ipv6_address,
                Interface.ipv6_gateway, Interface.ipv6_dns, Interface.ipv6_prefix, Interface.ports_filtered,
                Interface.ports_opened, Interface.ports_closed, Interface.host_id, EntityMetadata.couchdb_id,\
                EntityMetadata.revision, EntityMetadata.update_time, EntityMetadata.update_user,\
                EntityMetadata.update_action, EntityMetadata.creator, EntityMetadata.create_time,\
                EntityMetadata.update_controller_action, EntityMetadata.owner)

        query = self._session.query(interface_bundle).\
                outerjoin(EntityMetadata, EntityMetadata.id == Interface.entity_metadata_id)

        query = apply_search_filter(query, self.COLUMNS_MAP, None, interface_filter, self.STRICT_FILTERING)

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
                'owner': interface.owner,
                'hostnames': interface.hostnames,
                'network_segment': interface.network_segment,
                'ipv4': {'address': interface.ipv4_address,
                         'gateway': interface.ipv4_gateway,
                         'DNS': interface.ipv4_dns.split(',') if interface.ipv4_dns else [],
                         'mask': interface.ipv4_mask},
                'ipv6': {'address': interface.ipv6_address,
                         'gateway': interface.ipv6_gateway,
                         'DNS': interface.ipv6_dns.split(',') if interface.ipv6_dns else [],
                         'prefix': interface.ipv6_prefix},
                'ports': {'filtered': interface.ports_filtered,
                          'opened': interface.ports_opened,
                          'closed': interface.ports_closed},
                'metadata': {
                    'update_time': interface.update_time,
                    'update_user': interface.update_user,
                    'update_action': interface.update_action,
                    'creator': interface.creator,
                    'create_time': interface.create_time,
                    'update_controller_action': interface.update_controller_action,
                    'owner': interface.owner
                },
                'host_id': interface.host_id}
            }
