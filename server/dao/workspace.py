# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file "doc/LICENSE" for the license information

from server.dao.base import FaradayDAO
from server.utils.database import (
    apply_search_filter,
    get_count,
    paginate
)
from server.utils import logger

from sqlalchemy.orm.query import Bundle
from server.models import db, Workspace


class WorkspaceDAO(object):

    MAPPED_ENTITY = Workspace

    COLUMNS_MAP = {
        "create_date": [Workspace.create_date],
        "creator": [Workspace.creator],
        "customer": [Workspace.customer],
        "description": [Workspace.description],
        "disabled": [Workspace.disabled],
        "end_date": [Workspace.end_date],
        "name": [Workspace.name],
        "public": [Workspace.public],
        "scope": [Workspace.scope],
        "start_date": [Workspace.start_date],
        "update_date": [Workspace.update_date]
    }

    STRICT_FILTERING = ["name", "creator", "customer", "disabled",
                        "public", "update_date"]

    def __init__(self):
        self._logger = logger.get_logger(self)
        self._session = db.session
        self._couchdb = None

    def get_all(self):
        self.__check_valid_operation()
        return self._session.query(self.MAPPED_ENTITY)

    def __check_valid_operation(self):
        if self.MAPPED_ENTITY is None:
            raise RuntimeError('Invalid operation')

    def save(self, obj):
        self._session.add(obj)
        self._session.commit()

    def list(self, search=None, page=0, page_size=0, order_by=None,
             order_dir=None, workspace_filter={}):

        results, count = self.__query_database(search, page, page_size,
                                               order_by, order_dir,
                                               workspace_filter)
        rows = [self.__get_workspace_data(result.workspace)
                for result in results]

        result = {
            "total_rows": count,
            "rows": rows
        }

        return result

    def __query_database(self, search=None, page=0, page_size=0,
                         order_by=None, order_dir=None, workspace_filter={}):

        workspace_bundle = Bundle('workspace',
                                  Workspace.create_date,
                                  Workspace.creator,
                                  Workspace.customer,
                                  Workspace.description,
                                  Workspace.disabled,
                                  Workspace.end_date,
                                  Workspace.name,
                                  Workspace.public,
                                  Workspace.scope,
                                  Workspace.start_date,
                                  Workspace.update_date)

        query = self._session.query(workspace_bundle)

        query = apply_search_filter(query, self.COLUMNS_MAP, search,
                                    workspace_filter, self.STRICT_FILTERING)
        count = get_count(query, count_col=Workspace.name)

        if page_size:
            query = paginate(query, page, page_size)

        results = query.all()

        return results, count

    def __get_workspace_data(self, workspace):

        return {
            "create_date": workspace.create_date,
            "creator": workspace.creator,
            "customer": workspace.customer,
            "description": workspace.description,
            "disabled": workspace.disabled,
            "end_date": workspace.end_date,
            "name": workspace.name,
            "public": workspace.public,
            "scope": workspace.scope,
            "start_date": workspace.start_date,
            "update_date": workspace.update_date
        }
