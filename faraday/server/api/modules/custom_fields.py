# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import Blueprint
from marshmallow import fields

from faraday.server.models import CustomFieldsSchema
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView
)


custom_fields_schema_api = Blueprint('custom_fields_schema_api', __name__)


class CustomFieldsSchemaSchema(AutoSchema):

    id = fields.Integer(dump_only=True, attribute='id')
    field_name = fields.String(attribute='field_name', required=True)
    field_type = fields.String(attribute='field_type', required=True)
    field_metadata = fields.String(attribute='field_metadata', allow_none=True)
    field_display_name = fields.String(attribute='field_display_name', required=True)
    field_order = fields.Integer(attribute='field_order', required=True)
    table_name = fields.String(attribute='table_name', required=True)

    class Meta:
        model = CustomFieldsSchema
        fields = ('id',
                  'field_name',
                  'field_type',
                  'field_metadata',
                  'field_display_name',
                  'field_order',
                  'table_name'
                  )


class CustomFieldsSchemaView(ReadWriteView):
    route_base = 'custom_fields_schema'
    model_class = CustomFieldsSchema
    schema_class = CustomFieldsSchemaSchema

    def _update_object(self, obj, data, **kwargs):
        """
            Field name must be read only
        """
        for read_only_key in ['field_name', 'table_name', 'field_type']:
            if read_only_key in data:
                data.pop(read_only_key)
        return super()._update_object(obj, data)


CustomFieldsSchemaView.register(custom_fields_schema_api)
