import random
import factory
import datetime

import pytz
from factory.fuzzy import (
    FuzzyChoice,
    FuzzyNaiveDateTime,
    FuzzyInteger,
    FuzzyText,
    FuzzyDateTime,
)
from server.models import (
    db,
    Command,
    Credential,
    EntityMetadata,
    Host,
    License,
    Service,
    SourceCode,
    User,
    Vulnerability,
    VulnerabilityCode,
    VulnerabilityWeb,
    Workspace,
)

# Make partials for start and end date. End date must be after start date
FuzzyStartTime = lambda: (
    FuzzyNaiveDateTime(
        datetime.datetime.now() - datetime.timedelta(days=40),
        datetime.datetime.now() - datetime.timedelta(days=20),
    )
)
FuzzyEndTime = lambda: (
    FuzzyNaiveDateTime(
        datetime.datetime.now() - datetime.timedelta(days=19),
        datetime.datetime.now()
    )
)



class FaradayFactory(factory.alchemy.SQLAlchemyModelFactory):

    # id = factory.Sequence(lambda n: n)
    pass

    @classmethod
    def build_dict(cls, **kwargs):
        ret = factory.build(dict, FACTORY_CLASS=cls)
        try:
            # creator is an user instance, that isn't serializable. Ignore it
            del ret['creator']
        except KeyError:
            pass
        return ret


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


class WorkspaceObjectFactory(FaradayFactory):
    workspace = factory.SubFactory(WorkspaceFactory)
    creator = factory.SubFactory(UserFactory)

    @classmethod
    def build_dict(cls, **kwargs):
        ret = super(WorkspaceObjectFactory, cls).build_dict(**kwargs)
        del ret['workspace']  # It is passed in the URL, not in POST data
        return ret


class HostFactory(WorkspaceObjectFactory):
    ip = factory.Faker('ipv4')
    description = FuzzyText()
    os = FuzzyChoice(['Linux', 'Windows', 'OSX', 'Android', 'iOS'])
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Host
        sqlalchemy_session = db.session


class EntityMetadataFactory(WorkspaceObjectFactory):
    couchdb_id = factory.Sequence(lambda n: '{0}.1.2'.format(n))

    class Meta:
        model = EntityMetadata
        sqlalchemy_session = db.session


class ServiceFactory(WorkspaceObjectFactory):
    name = FuzzyText()
    description = FuzzyText()
    port = FuzzyInteger(1, 65535)
    protocol = FuzzyChoice(['TCP', 'UDP'])
    host = factory.SubFactory(HostFactory)
    status = FuzzyChoice(Service.STATUSES)
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Service
        sqlalchemy_session = db.session


class SourceCodeFactory(WorkspaceObjectFactory):
    filename = FuzzyText()

    class Meta:
        model = SourceCode
        sqlalchemy_session = db.session


class VulnerabilityGenericFactory(WorkspaceObjectFactory):
    name = FuzzyText()
    description = FuzzyText()
    creator = factory.SubFactory(UserFactory)
    severity = FuzzyChoice(['critical', 'high'])


class VulnerabilityFactory(VulnerabilityGenericFactory):

    host = factory.SubFactory(HostFactory)
    service = factory.SubFactory(ServiceFactory)

    @classmethod
    def _after_postgeneration(cls, obj, create, results=None):
        super(VulnerabilityFactory, cls)._after_postgeneration(
            obj, create, results)
        if obj.host and obj.service:
            # Setting both service and host to a vuln is not allowed.
            # This will pick one of them randomly.
            # TODO: Check is this is recommended
            if random.choice([True, False]):
                obj.host = None
            else:
                obj.service = None

    class Meta:
        model = Vulnerability
        sqlalchemy_session = db.session


class VulnerabilityWebFactory(VulnerabilityGenericFactory):
    method = FuzzyChoice(['GET', 'POST', 'PUT', 'PATCH' 'DELETE'])
    parameter_name = FuzzyText()
    service = factory.SubFactory(ServiceFactory)

    class Meta:
        model = VulnerabilityWeb
        sqlalchemy_session = db.session


class VulnerabilityCodeFactory(VulnerabilityGenericFactory):
    start_line = FuzzyInteger(1, 5000)
    source_code = factory.SubFactory(SourceCodeFactory)

    class Meta:
        model = VulnerabilityCode
        sqlalchemy_session = db.session


class CredentialFactory(WorkspaceObjectFactory):
    username = FuzzyText()
    password = FuzzyText()

    class Meta:
        model = Credential
        sqlalchemy_session = db.session


class CommandFactory(WorkspaceObjectFactory):
    command = FuzzyText()
    end_date = FuzzyDateTime(datetime.datetime.utcnow().replace(tzinfo=pytz.utc) + datetime.timedelta(20), datetime.datetime.utcnow().replace(tzinfo=pytz.utc) + datetime.timedelta(30))
    start_date = FuzzyDateTime(datetime.datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.timedelta(30), datetime.datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.timedelta(20))
    ip = FuzzyText()
    user = FuzzyText()
    hostname = FuzzyText()

    class Meta:
        model = Command
        sqlalchemy_session = db.session


class LicenseFactory(FaradayFactory):
    product = FuzzyText()
    start_date = FuzzyStartTime()
    end_date = FuzzyEndTime()
    type = FuzzyText()

    class Meta:
        model = License
        sqlalchemy_session = db.session

    @classmethod
    def build_dict(cls, **kwargs):
        # Ugly hack to JSON-serialize datetimes
        ret = super(LicenseFactory, cls).build_dict(**kwargs)
        ret['start_date'] = ret['start_date'].isoformat()
        ret['end_date'] = ret['end_date'].isoformat()
        return ret
