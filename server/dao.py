# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import server.database

from sqlalchemy import distinct
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.query import Bundle
from sqlalchemy.sql import func, asc, desc, expression
from server.models import Host, Interface, Service, Vulnerability, EntityMetadata
from server.utils.debug import Timer


import cProfile
import StringIO
import pstats
import contextlib

@contextlib.contextmanager
def profiled():
    pr = cProfile.Profile()
    pr.enable()
    yield
    pr.disable()
    s = StringIO.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats()
    # uncomment this to see who's calling what
    # ps.print_callers()
    print(s.getvalue())

class FaradayDAO(object):
    MAPPED_ENTITY = None
    COLUMNS_MAP = {}

    def __init__(self, workspace):
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

    def paginate_query(self, query, page, page_size):
        return query.limit(page_size).offset(page * page_size)

    def sort_query(self, query, order_field, order_dir, default=None):
        order_cols = self.COLUMNS_MAP.get(order_field, None)

        if order_cols is not None and len(order_cols) > 0:
            if order_dir in ('asc', 'desc'):
                dir_func = asc if order_dir == 'asc' else desc
                order_cols = map(dir_func, order_cols)
        else:
            order_cols = [default] if default is not None else None

        return query.order_by(*order_cols) if order_cols else query

    def filter_query(self, query, search=None, vuln_filter={}):
        print search
        print vuln_filter

        if any(map(lambda attr: attr not in self.COLUMNS_MAP, vuln_filter)):
            raise Exception('invalid filter')

        if search is not None and len(search) > 0:
            fts_like_str = '%' + search + '%'
        else:
            fts_like_str = None

        sql_filter = None
        for attribute in self.COLUMNS_MAP:
            if attribute in vuln_filter:
                like_str = u'%' + vuln_filter.get(attribute) + u'%'
            elif fts_like_str is not None:
                like_str = fts_like_str
            else:
                continue

            for column in self.COLUMNS_MAP.get(attribute):
                if isinstance(column, basestring):
                    continue
                if sql_filter is None:
                    sql_filter = column.like(like_str)
                else:
                    sql_filter = sql_filter | column.like(like_str)

        if sql_filter is not None:
            return query.filter(sql_filter)
        else:
            return query
    
    def get_total_count(self, query, count_column=None):
        with Timer('query.count'):
            if count_column is None:
                count_q = query.statement.with_only_columns([func.count()])
            else:
                count_q = query.statement.with_only_columns([func.count(distinct(count_column))])
            count_q = count_q.order_by(None).group_by(None)
            count = self._session.execute(count_q).scalar()

        print count
        return count


class HostDAO(FaradayDAO):
    MAPPED_ENTITY = Host
    COLUMNS_MAP = {
        "name":     [Host.name],
        "services": ["open_services_count"],
        "vulns":    ["vuln_count"],
        "os":       [Host.os],
        "owned":    [],
    }

    def list(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, host_filter={}):
        return self.__get_hosts(search, page, page_size, order_by, order_dir, host_filter)

    def __get_hosts(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, host_filter={}):
        host_bundle = Bundle('host', Host.name, Host.os, Host.description, EntityMetadata.couchdb_id,\
            EntityMetadata.revision, EntityMetadata.update_time, EntityMetadata.update_user,\
            EntityMetadata.update_action, EntityMetadata.creator, EntityMetadata.create_time,\
            EntityMetadata.update_controller_action,\
            func.count(distinct(Vulnerability.id)).label('vuln_count'),\
            func.count(distinct(Service.id)).label('open_services_count'))

        query = self._session.query(host_bundle)\
                             .outerjoin(EntityMetadata, EntityMetadata.id == Host.entity_metadata_id)\
                             .outerjoin(Vulnerability, Host.id == Vulnerability.host_id)\
                             .outerjoin(Service, (Host.id == Service.host_id) & (Service.status.in_(('open', 'running'))))\
                             .group_by(Host.id)

        query = self.sort_query(query, order_by, order_dir, default=Host.id)
        query = self.filter_query(query, search, host_filter)

        count = self.get_total_count(query, count_column=Host.id)

        if page_size:
            query = self.paginate_query(query, page, page_size)

        with profiled():
            results = query.all()

        rows =  [{
            'id': r.host.couchdb_id,
            'key': r.host.couchdb_id,
            'value': {
                '_id': r.host.couchdb_id,
                '_rev': r.host.revision,
                'name': r.host.name,
                'os': r.host.os,
                'owned': '',
                'owner': False,
                'description': r.host.description,
                'default_gateway': None,
                'metadata': {
                    'update_time': r.host.update_time,
                    'update_user': r.host.update_user,
                    'update_action': r.host.update_action,
                    'creator': r.host.creator,
                    'create_time': r.host.create_time,
                    'update_controller_action': r.host.update_controller_action,
                    'owner': ''
                },
                'vulns': r.host.vuln_count,
                'services': r.host.open_services_count,
            }} for r in results]

        return { 'total_rows': count, 'rows': rows }

    def __get_hosts_summary(self):
        result = self._session.query(Host.name,
                                     Host.os,
                                     Interface.ipv4_address,
                                     Interface.ipv4_mask,
                                     Interface.ipv6_address).join(Host.interfaces).all()
        return [ { 'name': name, 'os': os, 'ipv4': { 'address': ipv4_addr, 'mask': ipv4_mask }, 'ipv6': ipv6 } for name, os, ipv4_addr, ipv4_mask, ipv6 in result ]

    def get(self, hostname):
        return {}

class InterfaceDAO(FaradayDAO):
    MAPPED_ENTITY = Interface

class ServiceDAO(FaradayDAO):
    MAPPED_ENTITY = Service

    def list(self, port=None):
        return self.__get_services_by_host(port)

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
        
class VulnerabilityDAO(FaradayDAO):
    MAPPED_ENTITY = Vulnerability
    COLUMNS_MAP = {
        "date":             [],
        "confirmed":        [Vulnerability.confirmed],
        "name":             [Vulnerability.name],
        "severity":         [Vulnerability.severity],
        "service":          [Service.ports, Service.protocol, Service.name],
        "target":           [Host.name],
        "desc":             [Vulnerability.description],
        "resolution":       [Vulnerability.resolution],
        "data":             [Vulnerability.data],
        "owner":            [],
        "easeofresolution": [Vulnerability.easeofresolution],
        "status":           [],
        "website":          [],
        "path":             [],
        "request":          [],
        "refs":             [Vulnerability.refs],
        "tags":             [],
        "evidence":         [],
        "hostnames":        [Interface.hostnames],
        "impact":           [],
        "method":           [],
        "params":           [],
        "pname":            [],
        "query":            [],
        "response":         [],
        "web":              [],
        "issuetracker":     []
    }

    def list(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, vuln_filter={}):
        return self.__get_all_vulns(search, page, page_size, order_by, order_dir, vuln_filter)

    def __get_all_vulns(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, vuln_filter={}):
        def get_own_id(couchdb_id):
            return couchdb_id.split('.')[-1]
        def get_parent_id(couchdb_id):
            return '.'.join(couchdb_id.split('.')[:-1])

        # Instead of using SQLAlchemy ORM facilities to fetch rows, we bundle involved columns for
        # organizational and MAINLY performance reasons. Doing it this way, we improve retrieving
        # times from large workspaces almost 2x.
        vuln_bundle = Bundle('vuln', Vulnerability.name.label('v_name'), Vulnerability.confirmed, Vulnerability.data,\
            Vulnerability.description, Vulnerability.easeofresolution, Vulnerability.impact_accountability,\
            Vulnerability.impact_availability, Vulnerability.impact_confidentiality, Vulnerability.impact_integrity,\
            Vulnerability.refs, Vulnerability.resolution, Vulnerability.severity, EntityMetadata.couchdb_id,\
            EntityMetadata.revision, EntityMetadata.create_time, EntityMetadata.creator, EntityMetadata.owner,\
            EntityMetadata.update_action, EntityMetadata.update_controller_action, EntityMetadata.update_time,\
            EntityMetadata.update_user, Vulnerability.web_vulnerability)
        service_bundle = Bundle('service', Service.name.label('s_name'), Service.ports, Service.protocol)
        host_bundle = Bundle('host', Host.name)

        # IMPORTANT: OUTER JOINS on those tables is IMPERATIVE. Changing them could result in loss of
        # data. For example, on vulnerabilities not associated with any service and instead to its host
        # directly.
        query = self._session.query(vuln_bundle, 
                                    service_bundle,
                                    host_bundle,
                                    func.group_concat(Interface.hostnames))\
                             .group_by(Vulnerability.id)\
                             .outerjoin(EntityMetadata, EntityMetadata.id == Vulnerability.entity_metadata_id)\
                             .outerjoin(Service, Service.id == Vulnerability.service_id)\
                             .outerjoin(Host, Host.id == Vulnerability.host_id)\
                             .join(Interface, Interface.host_id == Host.id)

        query = self.sort_query(query, order_by, order_dir, default=Vulnerability.id)
        query = self.filter_query(query, search, vuln_filter)
        count = self.get_total_count(query)

        if page_size:
            query = self.paginate_query(query, page, page_size)

        with profiled():
            results = query.all()

        with Timer('query.build_list'):
            vuln_list = [ {
                'id': v.couchdb_id,
                'key': v.couchdb_id,
                'value': {
                    '_id': v.couchdb_id,
                    '_rev': v.revision,
                    'confirmed': v.confirmed,
                    'data': v.data,
                    'desc': v.description,
                    'easeofresolution': v.easeofresolution,
                    'impact': {
                        'accountability': v.impact_accountability,
                        'availability': v.impact_availability,
                        'confidentiality': v.impact_confidentiality,
                        'integrity': v.impact_integrity
                    },
                    'issuetracker': {},
                    'metadata': {
                        'create_time': v.create_time,
                        'creator': v.creator,
                        'owner': v.owner,
                        'update_action': v.update_action,
                        'update_controller_action': v.update_controller_action,
                        'update_time': v.update_time,
                        'update_user': v.update_user
                    },
                    'name': v.v_name,
                    'obj_id': get_own_id(v.couchdb_id),
                    'owned': False,
                    'owner': None,
                    'parent': get_parent_id(v.couchdb_id),
                    'refs': v.refs.split(',') if v.refs else [],
                    'resolution': v.resolution,
                    'severity': v.severity,
                    'tags': [],
                    'type': 'VulnerabilityWeb' if v.web_vulnerability else 'Vulnerability',
                    'target': h.name,
                    'hostnames': i_hostnames.split(','),
                    'service': "(%s/%s) %s" % (s.ports, s.protocol, s.s_name) if s.ports else ''
                }
            } for v, s, h, i_hostnames in results ]

        response = {
            'vulnerabilities': vuln_list,
            'count': count 
        }

        return response

