# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from server.dao.base import FaradayDAO
from server.utils.database import paginate, sort_results, apply_search_filter, get_count

from sqlalchemy.orm.query import Bundle
from sqlalchemy.sql import func
from server.models import Host, Interface, Service, Vulnerability, EntityMetadata
from server.utils.debug import Timer, profiled


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
        results, count = self.__query_database(search, page, page_size, order_by, order_dir, vuln_filter)

        with Timer('query.build_list'):
            vuln_list = [self.__get_vuln_data(v, s, h, hn) for v, s, h, hn in results]

        response = {
            'vulnerabilities': vuln_list,
            'count': count 
        }

        return response

    def __query_database(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, vuln_filter={}):
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

        # Apply pagination, sorting and filtering options to the query
        query = sort_results(query, self.COLUMNS_MAP, order_by, order_dir, default=Vulnerability.id)
        query = apply_search_filter(query, self.COLUMNS_MAP, search, vuln_filter)
        count = get_count(query)

        if page_size:
            query = paginate(query, page, page_size)

        with profiled():
            results = query.all()

        return results, count

    def __get_vuln_data(self, vuln, service, host, hostnames):
        def get_own_id(couchdb_id):
            return couchdb_id.split('.')[-1]
        def get_parent_id(couchdb_id):
            return '.'.join(couchdb_id.split('.')[:-1])

        return {
            'id': vuln.couchdb_id,
            'key': vuln.couchdb_id,
            'value': {
                '_id': vuln.couchdb_id,
                '_rev': vuln.revision,
                'confirmed': vuln.confirmed,
                'data': vuln.data,
                'desc': vuln.description,
                'easeofresolution': vuln.easeofresolution,
                'impact': {
                    'accountability': vuln.impact_accountability,
                    'availability': vuln.impact_availability,
                    'confidentiality': vuln.impact_confidentiality,
                    'integrity': vuln.impact_integrity
                },
                'issuetracker': {},
                'metadata': {
                    'create_time': vuln.create_time,
                    'creator': vuln.creator,
                    'owner': vuln.owner,
                    'update_action': vuln.update_action,
                    'update_controller_action': vuln.update_controller_action,
                    'update_time': vuln.update_time,
                    'update_user': vuln.update_user
                },
                'name': vuln.v_name,
                'obj_id': get_own_id(vuln.couchdb_id),
                'owned': False,
                'owner': None,
                'parent': get_parent_id(vuln.couchdb_id),
                'refs': vuln.refs.split(',') if vuln.refs else [],
                'resolution': vuln.resolution,
                'severity': vuln.severity,
                'tags': [],
                'type': 'VulnerabilityWeb' if vuln.web_vulnerability else 'Vulnerability',
                'target': host.name,
                'hostnames': hostnames.split(','),
                'service': "(%s/%s) %s" % (service.ports, service.protocol, service.s_name) if service.ports else ''
            }}

    def count(self, group_by=None):
        with Timer('query.total_count'):
            total_count = self._session.query(func.count(Vulnerability.id)).scalar()

        # Return total amount of services if no group-by field was provided
        if group_by is None:
            return { 'total_count': total_count }

        # Otherwise return the amount of services grouped by the field specified
        # Don't perform group-by counting on fields with less or more than 1 column mapped to it
        if group_by not in VulnerabilityDAO.COLUMNS_MAP or\
           len(VulnerabilityDAO.COLUMNS_MAP.get(group_by)) != 1:
            return None

        col = VulnerabilityDAO.COLUMNS_MAP.get(group_by)[0]
        query = self._session.query(col, func.count())\
                             .group_by(col)

        with Timer('query.group_count'):
            res = query.all()

        return { 'total_count': total_count,
                 'groups': [ { group_by: value, 'count': count } for value, count in res ] }
        

