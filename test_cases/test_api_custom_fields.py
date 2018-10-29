from test_cases.factories import CustomFieldsSchemaFactory
from server.api.modules.custom_fields import CustomFieldsSchemaView


@pytest.mark.usefixtures('logged_user')
class TestVulnerabilityCustomFields(ReadOnlyAPITests):
    model = Vulnerability
    factory = CustomFieldsSchemaFactory
    api_endpoint = 'vulns'
    #unique_fields = ['ip']
    #update_fields = ['ip', 'description', 'os']
    view_class = CustomFieldsSchemaView

    def test_custom_fields_data(self, session, test_client):
        add_text_field = CustomFieldsSchemaFactory.create(
            table='vulnerability',
            field_name='cvss',
            field_type='text',
            field_display_name='CVSS',
        )
        session.add(add_text_field)
        session.commit()

        res = test_client.get('/v2/custom_fields_schema')
        import ipdb; ipdb.set_trace()
