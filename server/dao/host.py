# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from server.dao.base import FaradayDAO
from server.utils.database import paginate, sort_results, apply_search_filter, get_count

from sqlalchemy import distinct
from sqlalchemy.orm.query import Bundle
from sqlalchemy.sql import func
from server.models import Host, Interface, Service, Vulnerability, EntityMetadata


class HostDAO(FaradayDAO):
    MAPPED_ENTITY = Host
    COLUMNS_MAP = {
        "couchid":  [EntityMetadata.couchdb_id],
        "name":     [Host.name],
        "service":  [Service.name],
        "services": ["open_services_count"],
        "vulns":    ["vuln_count"],
        "os":       [Host.os],
        "owned":    [Host.owned],
        "command_id":[EntityMetadata.command_id]
    }
    STRICT_FILTERING = ["service", "couchid", "command_id"]

    def list(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, host_filter={}):
        results, count = self.__query_database(search, page, page_size, order_by, order_dir, host_filter)

        rows = [ self.__get_host_data(result.host) for result in results ]

        result = {
            'total_rows': count,
            'rows': rows
        }

        return result

    def __query_database(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, host_filter={}):
        host_bundle = Bundle('host', Host.id, Host.name, Host.os, Host.description, Host.owned,\
            Host.default_gateway_ip, Host.default_gateway_mac, EntityMetadata.couchdb_id,\
            EntityMetadata.revision, EntityMetadata.update_time, EntityMetadata.update_user,\
            EntityMetadata.update_action, EntityMetadata.creator, EntityMetadata.create_time,\
            EntityMetadata.update_controller_action, EntityMetadata.owner, EntityMetadata.command_id,\
            func.group_concat(distinct(Interface.id)).label('interfaces'),\
            func.count(distinct(Vulnerability.id)).label('vuln_count'),\
            func.count(distinct(Service.id)).label('open_services_count'))

        query = self._session.query(host_bundle)\
                             .outerjoin(EntityMetadata, EntityMetadata.id == Host.entity_metadata_id)\
                             .outerjoin(Interface, Host.id == Interface.host_id)\
                             .outerjoin(Vulnerability, Host.id == Vulnerability.host_id)\
                             .outerjoin(Service, (Host.id == Service.host_id) & (Service.status.in_(('open', 'running', 'opened'))))\
                             .group_by(Host.id)

        # Apply pagination, sorting and filtering options to the query
        query = sort_results(query, self.COLUMNS_MAP, order_by, order_dir, default=Host.id)
        query = apply_search_filter(query, self.COLUMNS_MAP, search, host_filter, self.STRICT_FILTERING)
        count = get_count(query, count_col=Host.id)

        if page_size:
            query = paginate(query, page, page_size)

        results = query.all()

        return results, count

    def __get_host_data(self, host):
        return {
            'id': host.couchdb_id,
            'key': host.couchdb_id,
            '_id': host.id,
            'value': {
                '_id': host.couchdb_id,
                '_rev': host.revision,
                'name': host.name,
                'os': host.os,
                'owned': host.owned,
                'owner': host.owner,
                'description': host.description,
                'default_gateway': [host.default_gateway_ip, host.default_gateway_mac],
                'metadata': {
                    'update_time': host.update_time,
                    'update_user': host.update_user,
                    'update_action': host.update_action,
                    'creator': host.creator,
                    'create_time': host.create_time,
                    'update_controller_action': host.update_controller_action,
                    'owner': host.owner,
                    'command_id': host.command_id
                },
                'vulns': host.vuln_count,
                'services': host.open_services_count,
                'interfaces': map(int, host.interfaces.split(',')) if host.interfaces else []  }}

    def count(self, group_by=None):
        total_count = self._session.query(func.count(Host.id)).scalar()

        # Return total amount of services if no group-by field was provided
        result_count = { 'total_count': total_count }
        if group_by is None:
            return result_count

        # Otherwise return the amount of services grouped by the field specified
        # Strict restriction is applied for this entity
        if group_by not in ['name', 'os']:
            return None

        col = HostDAO.COLUMNS_MAP.get(group_by)[0]
        query = self._session.query(col, func.count()).group_by(col)
        res = query.all()

        result_count['groups'] = [ { group_by: value, 'count': count } for value, count in res ]

        return result_count

