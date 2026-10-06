"""
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint
from marshmallow import fields
from sqlalchemy import text

# Local application imports
from faraday.server.models import CustomFieldsSchema, db
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView,
    BulkDeleteMixin,
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


class CustomFieldsSchemaView(ReadWriteView, BulkDeleteMixin):
    route_base = 'custom_fields_schema'
    model_class = CustomFieldsSchema
    schema_class = CustomFieldsSchemaSchema

    # Vulnerability and VulnerabilityTemplate both resolve their custom field
    # definitions with table_name='vulnerability' (see FaradayCustomField usage
    # in vulns_base.py and vulnerability_template.py), but each stores its own
    # values in its own physical custom_fields column. So a schema defined with
    # table_name='vulnerability' must be cleared from both physical tables.
    _PHYSICAL_TABLES_BY_SCHEMA_TABLE_NAME = {
        'vulnerability': ('vulnerability', 'vulnerability_template'),
        'vulnerability_template': ('vulnerability_template',),
    }

    @staticmethod
    def _check_post_only_data(data):
        for read_only_key in ['field_name', 'table_name', 'field_type']:
            data.pop(read_only_key, None)
        return data

    def _update_object(self, obj, data, **kwargs):
        """
            Field name must be read only
        """
        data = self._check_post_only_data(data)
        return super()._update_object(obj, data)

    @classmethod
    def _clear_custom_field_values(cls, table_name: str, field_name: str):
        """Remove field_name key from custom_fields JSON in every physical table sharing this field definition."""
        for physical_table in cls._PHYSICAL_TABLES_BY_SCHEMA_TABLE_NAME.get(table_name, ()):
            db.session.execute(
                text(
                    f"UPDATE {physical_table} SET custom_fields = custom_fields - :key"  # noqa: S608 # nosec B608
                    f" WHERE custom_fields ? :key"
                ),
                {'key': field_name},
            )

    def _perform_delete(self, obj, workspace_name=None):
        self._clear_custom_field_values(obj.table_name, obj.field_name)
        super()._perform_delete(obj, workspace_name)

    def _perform_bulk_delete(self, values, **kwargs):
        objs = self.model_class.query.filter(self.model_class.id.in_(values)).all()
        for obj in objs:
            self._clear_custom_field_values(obj.table_name, obj.field_name)
        return super()._perform_bulk_delete(values, **kwargs)


CustomFieldsSchemaView.register(custom_fields_schema_api)
