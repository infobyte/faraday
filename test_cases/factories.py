import factory
from pytest_factoryboy import register
from server.models import Vulnerability, Workspace


class VulnerabilityFactory(factory.Factory):

    class Meta:
        model = Vulnerability


class WorkspaceFactory(factory.Factory):

    class Meta:
        model = Workspace


register(VulnerabilityFactory)
register(WorkspaceFactory)
