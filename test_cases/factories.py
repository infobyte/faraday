import random
import factory
import datetime
import unicodedata

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
    Host,
    Hostname,
    License,
    PolicyViolation,
    Reference,
    Service,
    SourceCode,
    Tag,
    User,
    Vulnerability,
    VulnerabilityCode,
    VulnerabilityTemplate,
    VulnerabilityWeb,
    Workspace,
    ReferenceTemplate, CommandObject)

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

all_unicode = ''.join(unichr(i) for i in xrange(65536))
UNICODE_LETTERS = ''.join(c for c in all_unicode if unicodedata.category(c) == 'Lu' or unicodedata.category(c) == 'Ll')


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


class HostnameFactory(WorkspaceObjectFactory):
    name = factory.Faker('domain_name')
    host = factory.SubFactory(HostFactory)

    class Meta:
        model = Hostname
        sqlalchemy_session = db.session


class PolicyViolationFactory(WorkspaceObjectFactory):
    name = FuzzyText()

    class Meta:
        model = PolicyViolation
        sqlalchemy_session = db.session


class ReferenceFactory(WorkspaceObjectFactory):
    name = FuzzyText()

    class Meta:
        model = Reference
        sqlalchemy_session = db.session


class ReferenceTemplateFactory(FaradayFactory):
    name = FuzzyText()

    class Meta:
        model = ReferenceTemplate
        sqlalchemy_session = db.session


class ServiceFactory(WorkspaceObjectFactory):
    name = FuzzyText()
    description = FuzzyText()
    port = FuzzyInteger(1, 65535)
    protocol = FuzzyChoice(['TCP', 'UDP'])
    host = factory.SubFactory(HostFactory, workspace=factory.SelfAttribute('..workspace'))
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


class HasParentHostOrService(object):
    """
    Mixins for objects that must have either a host or a service,
    but ont both, as a parent.

    By default it randomly select one of them and set the other to
    None, but this behavior can be modified as with other factory
    fields
    """

    @classmethod
    def attributes(cls, create=False, extra=None):
        if extra:
            if ('host' in extra and 'service' not in extra) or \
                    ('service' in extra and 'host' not in extra):
                raise ValueError('You should pass both service and host and '
                                 'set one of them to None to prevent random '
                                 'stuff to happen')
        return super(HasParentHostOrService, cls).attributes(create, extra)

    @classmethod
    def _after_postgeneration(cls, obj, create, results=None):
        super(HasParentHostOrService, cls)._after_postgeneration(
            obj, create, results)
        if isinstance(obj, dict):
            # This happens when built with build_dict
            return
        if obj.host and obj.service:
            # Setting both service and host to a vuln is not allowed.
            # This will pick one of them randomly.
            # TODO: Check is this is recommended
            if random.choice([True, False]):
                obj.host = None
            else:
                obj.service = None


class VulnerabilityFactory(HasParentHostOrService,
                           VulnerabilityGenericFactory):

    host = factory.SubFactory(HostFactory, workspace=factory.SelfAttribute('..workspace'))
    service = factory.SubFactory(ServiceFactory, workspace=factory.SelfAttribute('..workspace'))

    class Meta:
        model = Vulnerability
        sqlalchemy_session = db.session


class VulnerabilityWebFactory(VulnerabilityGenericFactory):
    method = FuzzyChoice(['GET', 'POST', 'PUT', 'PATCH' 'DELETE'])
    parameter_name = FuzzyText()
    service = factory.SubFactory(ServiceFactory, workspace=factory.SelfAttribute('..workspace'))

    class Meta:
        model = VulnerabilityWeb
        sqlalchemy_session = db.session


class VulnerabilityCodeFactory(VulnerabilityGenericFactory):
    start_line = FuzzyInteger(1, 5000)
    source_code = factory.SubFactory(SourceCodeFactory)

    class Meta:
        model = VulnerabilityCode
        sqlalchemy_session = db.session


class VulnerabilityTemplateFactory(FaradayFactory):
    # name = FuzzyText(chars=UNICODE_LETTERS)
    # description = FuzzyText(chars=UNICODE_LETTERS)
    name = FuzzyText()
    description = FuzzyText()
    severity = FuzzyChoice(VulnerabilityTemplate.SEVERITIES)
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = VulnerabilityTemplate
        sqlalchemy_session = db.session


class CredentialFactory(HasParentHostOrService, WorkspaceObjectFactory):
    host = factory.SubFactory(HostFactory, workspace=factory.SelfAttribute('..workspace'))
    service = None  # factory.SubFactory(ServiceFactory)
    username = FuzzyText()
    password = FuzzyText()

    class Meta:
        model = Credential
        sqlalchemy_session = db.session


class CommandObjectFactory(FaradayFactory):

    class Meta:
        model = CommandObject
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

    @factory.post_generation
    def attach_vuln_object(self, create, extracted, **kwargs):
        if create:
            host = HostFactory.create(workspace=self.workspace)
            vuln = VulnerabilityFactory.create(workspace=self.workspace, host=host, service=None, severity='low')
            db.session.flush()
            CommandObjectFactory.create(
                object_type='Vulnerability',
                object_id=vuln.id,
                command=self,
            )
            CommandObjectFactory.create(
                object_type='Host',
                object_id=host.id,
                command=self,
            )

class EmptyCommandFactory(FaradayFactory):
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


class TagFactory(FaradayFactory):
    name = FuzzyText()
    slug = FuzzyText()

    class Meta:
        model = Tag
        sqlalchemy_session = db.session
