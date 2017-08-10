import factory
from factory.fuzzy import FuzzyText
from pytest_factoryboy import register
from server.models import db, Vulnerability, Workspace


class VulnerabilityFactory(factory.alchemy.SQLAlchemyModelFactory):

    id = factory.Sequence(lambda n: n)
    name = FuzzyText()
    description = FuzzyText()

    class Meta:
        model = Vulnerability
        sqlalchemy_session = db.session


class WorkspaceFactory(factory.alchemy.SQLAlchemyModelFactory):

    id = factory.Sequence(lambda n: n)
    name = FuzzyText()

    class Meta:
        model = Workspace
        sqlalchemy_session = db.session


register(VulnerabilityFactory)
register(WorkspaceFactory)
