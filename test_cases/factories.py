import factory
from factory.fuzzy import (
    FuzzyText,
    FuzzyChoice
)
from pytest_factoryboy import register
from server.models import (
    db,
    Host,
    Service,
    Interface,
    Workspace,
    Credential,
    Vulnerability,
    EntityMetadata,
)


class FaradayFactory(factory.alchemy.SQLAlchemyModelFactory):

    id = factory.Sequence(lambda n: n)


class WorkspaceFactory(FaradayFactory):

    name = FuzzyText()

    class Meta:
        model = Workspace
        sqlalchemy_session = db.session


class HostFactory(FaradayFactory):
    name = FuzzyText()
    description = FuzzyText()
    os = FuzzyChoice(['Linux', 'Windows', 'OSX', 'Android', 'iOS'])

    class Meta:
        model = Host
        sqlalchemy_session = db.session


class EntityMetadataFactory(FaradayFactory):
    couchdb_id = factory.Sequence(lambda n: '{0}.1.2'.format(n))

    class Meta:
        model = EntityMetadata
        sqlalchemy_session = db.session


class InterfaceFactory(FaradayFactory):
    name = FuzzyText()
    description = FuzzyText()
    mac = FuzzyText()
    host = factory.SubFactory(HostFactory)

    class Meta:
        model = Interface
        sqlalchemy_session = db.session


class ServiceFactory(FaradayFactory):
    name = FuzzyText()
    description = FuzzyText()
    ports = FuzzyChoice(['443', '80', '22'])
    interface = factory.SubFactory(InterfaceFactory)
    host = factory.SubFactory(HostFactory)

    class Meta:
        model = Service
        sqlalchemy_session = db.session


class VulnerabilityFactory(FaradayFactory):

    name = FuzzyText()
    description = FuzzyText()
    host = factory.SubFactory(HostFactory)
    entity_metadata = factory.SubFactory(EntityMetadataFactory)
    service = factory.SubFactory(ServiceFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    vuln_type = FuzzyChoice(['Vulnerability', 'VulnerabilityWeb'])
    attachments = '[]'
    policyviolations = '[]'
    refs = '[]'

    class Meta:
        model = Vulnerability
        sqlalchemy_session = db.session


class CredentialFactory(FaradayFactory):
    username = FuzzyText()
    password = FuzzyText()

    class Meta:
        model = Credential
        sqlalchemy_session = db.session

register(WorkspaceFactory)
register(HostFactory)
register(ServiceFactory)
register(InterfaceFactory)
register(VulnerabilityFactory)
register(CredentialFactory)
