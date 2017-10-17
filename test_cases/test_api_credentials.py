from test_cases import factories
from test_api_workspaced_base import (
    ReadOnlyAPITests,
)
from server.api.modules.credentials import CredentialView
from server.models import Credential


class TestCredentialsAPIGeneric(ReadOnlyAPITests):
    model = Credential
    factory = factories.CredentialFactory
    view_class = CredentialView
    api_endpoint = 'credentials'
    update_fields = ['username', 'password']
