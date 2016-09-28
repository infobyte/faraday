# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import json

from server.dao.base import FaradayDAO
from server.utils.database import paginate, sort_results, apply_search_filter, get_count

from sqlalchemy import case
from sqlalchemy.sql import func
from sqlalchemy.orm.query import Bundle
from server.models import Host, Interface, Service, Vulnerability, EntityMetadata


class VulnerabilityDAO(FaradayDAO):
    MAPPED_ENTITY = Vulnerability
    COLUMNS_MAP = {
        "couchid":          [EntityMetadata.couchdb_id],
        "id":               [Vulnerability.id],
        "date":             [EntityMetadata.create_time], # TODO: fix search for this field
        "confirmed":        [Vulnerability.confirmed],
        "name":             [Vulnerability.name],
        "severity":         [Vulnerability.severity],
        "service":          [Service.ports, Service.protocol, Service.name],
        "target":           [Host.name],
        "desc":             [Vulnerability.description],
        "resolution":       [Vulnerability.resolution],
        "data":             [Vulnerability.data],
        "owner":            [EntityMetadata.owner],
        "owned":            [Vulnerability.owned],
        "easeofresolution": [Vulnerability.easeofresolution],
        "type":             [EntityMetadata.document_type],
        "status":           [],
        "website":          [Vulnerability.website],
        "path":             [Vulnerability.path],
        "request":          [Vulnerability.request],
        "refs":             [Vulnerability.refs],
        "tags":             [],
        "evidence":         [],
        "hostnames":        [Interface.hostnames],
        "impact":           [],
        "method":           [Vulnerability.method],
        "params":           [Vulnerability.params],
        "pname":            [Vulnerability.pname],
        "query":            [Vulnerability.query],
        "response":         [Vulnerability.response],
        "hostid":           [Host.id],
        "serviceid":        [Service.id],
        "interfaceid":      [Interface.id],
        "web":              [],
        "issuetracker":     [],
        "plugin":           [EntityMetadata.creator]
    }

    STRICT_FILTERING = ["type", "service", "couchid", "hostid", "serviceid", 'interfaceid', 'id']

    def list(self, search=None, page=0, page_size=0, order_by=None, order_dir=None, vuln_filter={}):
        results, count = self.__query_database(search, page, page_size, order_by, order_dir, vuln_filter)
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
        vuln_bundle = Bundle('vuln', Vulnerability.id.label('server_id'),Vulnerability.name.label('v_name'),\
            Vulnerability.confirmed, Vulnerability.data,\
            Vulnerability.description, Vulnerability.easeofresolution, Vulnerability.impact_accountability,\
            Vulnerability.impact_availability, Vulnerability.impact_confidentiality, Vulnerability.impact_integrity,\
            Vulnerability.refs, Vulnerability.resolution, Vulnerability.severity, Vulnerability.owned, Vulnerability.status,\
            Vulnerability.website, Vulnerability.path, Vulnerability.request, Vulnerability.response,\
            Vulnerability.method, Vulnerability.params, Vulnerability.pname, Vulnerability.query,\
            EntityMetadata.couchdb_id, EntityMetadata.revision, EntityMetadata.create_time, EntityMetadata.creator,\
            EntityMetadata.owner, EntityMetadata.update_action, EntityMetadata.update_controller_action,\
            EntityMetadata.update_time, EntityMetadata.update_user, EntityMetadata.document_type, EntityMetadata.command_id, Vulnerability.attachments)
        service_bundle = Bundle('service', Service.name.label('s_name'), Service.ports, Service.protocol, Service.id)
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
        query = self.__specialized_sort(query, order_by, order_dir)
        query = apply_search_filter(query, self.COLUMNS_MAP, search, vuln_filter, self.STRICT_FILTERING)
        count = get_count(query)

        if page_size:
            query = paginate(query, page, page_size)

        results = query.all()

        return results, count

    def __specialized_sort(self, query, order_by, order_dir):
        """ Before using sort_results(), handle special ordering cases
        for some fields """
        if order_by == 'severity':
            # For severity only, we choose a risk-based ordering
            # instead of a lexicographycally one
            column_map = {
                'severity': [case(
                    { 'unclassified': 0,
                      'info': 1,
                      'low': 2,
                      'med': 3,
                      'high': 4,
                      'critical': 5 },
                    value=Vulnerability.severity
                )]
            }
        else:
            column_map = self.COLUMNS_MAP

        return sort_results(query, column_map, order_by, order_dir, default=Vulnerability.id)

    def __get_vuln_data(self, vuln, service, host, hostnames):
        def get_own_id(couchdb_id):
            return couchdb_id.split('.')[-1]
        def get_parent_id(couchdb_id):
            return '.'.join(couchdb_id.split('.')[:-1])

        return {
            'id': vuln.couchdb_id,
            'key': vuln.couchdb_id,
            '_id': vuln.server_id,
            'value': {
                '_id': vuln.couchdb_id,
                '_rev': vuln.revision,
                'confirmed': vuln.confirmed,
                'data': vuln.data,
                'desc': vuln.description,
                'description': vuln.description,
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
                    'update_user': vuln.update_user,
                    'command_id': vuln.command_id
                },
                '_attachments': json.loads(vuln.attachments),
                'name': vuln.v_name,
                'obj_id': get_own_id(vuln.couchdb_id),
                'owned': vuln.owned,
                'owner': vuln.owner,
                'parent': get_parent_id(vuln.couchdb_id),
                'refs': json.loads(vuln.refs),
                'status': vuln.status,
                'website': vuln.website,
                'path': vuln.path,
                'request': vuln.request,
                'response': vuln.response,
                'method': vuln.method,
                'params': vuln.params,
                'pname': vuln.pname,
                'query': vuln.query,
                'resolution': vuln.resolution,
                'severity': vuln.severity,
                'tags': [],
                'type': vuln.document_type,
                'target': host.name,
                'hostnames': hostnames.split(',') if hostnames else '',
                'service': "(%s/%s) %s" % (service.ports, service.protocol, service.s_name) if service.ports else ''
            }}

    def count(self, group_by=None, search=None, vuln_filter={}):
        query = self._session.query(Vulnerability.vuln_type, func.count())\
                             .group_by(Vulnerability.vuln_type)
        query = apply_search_filter(query, self.COLUMNS_MAP, search, vuln_filter)
        total_count = dict(query.all())

        # Return total amount of services if no group-by field was provided
        result_count = { 'total_count':    sum(total_count.values()),
                         'web_vuln_count': total_count.get('VulnerabilityWeb', 0),
                         'vuln_count':     total_count.get('Vulnerability', 0), }

        if group_by is None:
            return result_count

        # Otherwise return the amount of services grouped by the field specified
        # Don't perform group-by counting on fields with less or more than 1 column mapped to it
        if group_by not in VulnerabilityDAO.COLUMNS_MAP or\
           len(VulnerabilityDAO.COLUMNS_MAP.get(group_by)) != 1:
            return None

        col = VulnerabilityDAO.COLUMNS_MAP.get(group_by)[0]
        vuln_bundle = Bundle('vuln', Vulnerability.id, col)
        query = self._session.query(vuln_bundle, func.count())\
                             .group_by(col)\
                             .outerjoin(EntityMetadata, EntityMetadata.id == Vulnerability.entity_metadata_id)

        query = apply_search_filter(query, self.COLUMNS_MAP, search, vuln_filter, self.STRICT_FILTERING)
        result = query.all()

        result_count['groups'] = [ { group_by: value[1], 'count': count } for value, count in result ]

        return result_count

