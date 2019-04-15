import pytest

from test_cases.factories import CustomFieldsSchemaFactory
from test_cases.test_api_non_workspaced_base import ReadOnlyAPITests

from server.api.modules.custom_fields import CustomFieldsSchemaView
from server.models import (
    CustomFieldsSchema
)

@pytest.mark.usefixtures('logged_user')
class TestVulnerabilityCustomFields(ReadOnlyAPITests):
    model = CustomFieldsSchema
    factory = CustomFieldsSchemaFactory
    api_endpoint = 'custom_fields_schema'
    #unique_fields = ['ip']
    #update_fields = ['ip', 'description', 'os']
    view_class = CustomFieldsSchemaView

    def test_custom_fields_data(self, session, test_client):
        add_text_field = CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='cvss',
            field_type='text',
            field_order=1,
            field_display_name='CVSS',
        )
        session.add(add_text_field)
        session.commit()

        res = test_client.get(self.url()) # '/v2/custom_fields_schema/')
        assert res.status_code == 200
        assert {u'table_name': u'vulnerability', u'id': add_text_field.id, u'field_type': u'text', u'field_name': u'cvss', u'field_display_name': u'CVSS', u'field_order': 1} in res.json
