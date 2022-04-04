"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
import flask_login
from flask import Blueprint
from marshmallow import fields

# Local application imports
from faraday.server.models import SearchFilter
from faraday.server.api.base import (
    ReadWriteView,
    AutoSchema,
    BulkDeleteMixin,
    BulkUpdateMixin,
)

searchfilter_api = Blueprint('searchfilter_api', __name__)


class SearchFilterSchema(AutoSchema):

    id = fields.Integer(dump_only=True, attribute='id')

    class Meta:
        model = SearchFilter
        fields = ('id', 'name',
                  'json_query', 'user_query')


class SearchFilterView(ReadWriteView, BulkDeleteMixin, BulkUpdateMixin):
    route_base = 'searchfilter'
    model_class = SearchFilter
    schema_class = SearchFilterSchema

    def _get_base_query(self):
        query = super()._get_base_query()
        return query.filter(SearchFilter.creator_id == flask_login.current_user.id)


SearchFilterView.register(searchfilter_api)
