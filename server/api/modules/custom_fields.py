# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from flask import Blueprint
from marshmallow import fields

from faraday.server.models import db, CustomFieldsSchema
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView,
)
from faraday.server.utils.database import get_or_create


custom_fields_schema_api = Blueprint('custom_fields_schema_api', __name__)


class CustomFieldsSchemaSchema(AutoSchema):

    class Meta:
        model = CustomFieldsSchema
        fields = ('id',
                  'field_name',
                  'field_type',
                  'field_display_name',
                  'field_order',
                  'table_name'
                  )


class CustomFieldsSchemaView(ReadWriteView):
    route_base = 'custom_fields_schema'
    model_class = CustomFieldsSchema
    schema_class = CustomFieldsSchemaSchema

    def _update_object(self, obj, data):
        """
            Field name must be read only
        """
        for read_only_key in ['field_name', 'table_name', 'field_type']:
            if read_only_key in data:
                data.pop(read_only_key)
        return super(CustomFieldsSchemaView, self)._update_object(obj, data)

CustomFieldsSchemaView.register(custom_fields_schema_api)
