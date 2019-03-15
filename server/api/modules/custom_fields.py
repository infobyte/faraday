# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from flask import Blueprint
from marshmallow import fields

from faraday.server.models import CustomFieldsSchema
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView,
)


custom_fields_schema_api = Blueprint('custom_fields_schema_api', __name__)


class CustomFieldsSchemaSchema(AutoSchema):

    class Meta:
        model = CustomFieldsSchema
        fields = ('field_name',
                  'field_type',
                  'field_display_name',
                  'field_order',
                  )


class CustomFieldsSchemaView(ReadWriteView):
    route_base = 'custom_fields_schema'
    model_class = CustomFieldsSchema
    schema_class = CustomFieldsSchemaSchema

CustomFieldsSchemaView.register(custom_fields_schema_api)
