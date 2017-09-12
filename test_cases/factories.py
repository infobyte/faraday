import factory
from factory.fuzzy import (
    FuzzyText,
    FuzzyChoice
)
from pytest_factoryboy import register
from server.models import (
    db,
    User,
    Host,
    Command,
    Service,
    Workspace,
    Credential,
    Vulnerability,
    EntityMetadata,
)


class FaradayFactory(factory.alchemy.SQLAlchemyModelFactory):

    id = factory.Sequence(lambda n: n)


class UserFactory(FaradayFactory):

    username = FuzzyText()

    class Meta:
        model = User
        sqlalchemy_session = db.session

class WorkspaceFactory(FaradayFactory):

    name = FuzzyText()
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Workspace
        sqlalchemy_session = db.session


class HostFactory(FaradayFactory):
    ip = FuzzyText()
    description = FuzzyText()
    os = FuzzyChoice(['Linux', 'Windows', 'OSX', 'Android', 'iOS'])
    workspace = factory.SubFactory(WorkspaceFactory)
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Host
        sqlalchemy_session = db.session


class EntityMetadataFactory(FaradayFactory):
    couchdb_id = factory.Sequence(lambda n: '{0}.1.2'.format(n))

    class Meta:
        model = EntityMetadata
        sqlalchemy_session = db.session


class ServiceFactory(FaradayFactory):
    name = FuzzyText()
    description = FuzzyText()
    port = FuzzyChoice(['443', '80', '22'])
    protocol = FuzzyChoice(['TCP', 'UDP'])
    host = factory.SubFactory(HostFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Service
        sqlalchemy_session = db.session


class VulnerabilityFactory(FaradayFactory):

    name = FuzzyText()
    description = FuzzyText()
    # host = factory.SubFactory(HostFactory)
    # service = factory.SubFactory(ServiceFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    creator = factory.SubFactory(UserFactory)
    severity = FuzzyChoice(['critical', 'high'])

    class Meta:
        model = Vulnerability
        sqlalchemy_session = db.session


class CredentialFactory(FaradayFactory):
    username = FuzzyText()
    password = FuzzyText()

    class Meta:
        model = Credential
        sqlalchemy_session = db.session


class CommandFactory(FaradayFactory):
    command = FuzzyText()

    class Meta:
        model = Command
        sqlalchemy_session = db.session

register(UserFactory)
register(WorkspaceFactory)
register(HostFactory)
register(ServiceFactory)
register(VulnerabilityFactory)
register(CredentialFactory)
