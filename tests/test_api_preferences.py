import pytest

from tests.test_api_non_workspaced_base import GenericAPITest
from tests.factories import UserFactory
from faraday.server.models import User
from faraday.server.api.modules.preferences import PreferencesView

pytest.fixture('logged_user')
class TestPreferences(GenericAPITest):
    model = User
    factory = UserFactory
    api_endpoint = 'preferences'
    view_class = PreferencesView

    def test_add_preference(self, test_client):
        data = {'preferences': {'field1': 1, 'field2': 'str1'}}
        response = test_client.post(self.url(), data=data)

        assert response.status_code == 201

        response = test_client.get(self.url())

        assert response.status_code == 200
        print("GET ", response.json)

