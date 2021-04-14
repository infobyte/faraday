'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from builtins import chr, range

import random
import string
import factory
import datetime
import itertools
import unicodedata
import time

import pytz
from factory.fuzzy import (
    BaseFuzzyAttribute,
    FuzzyChoice,
    FuzzyNaiveDateTime,
    FuzzyInteger,
    FuzzyText,
    FuzzyDateTime,
)
from faraday.server.models import (
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
    ReferenceTemplate,
    CommandObject,
    Comment,
    CustomFieldsSchema,
    Agent,
    AgentExecution,
    SearchFilter,
    Executor,
    Rule,
    Action,
    RuleAction,
    Condition)


# Make partials for start and end date. End date must be after start date
def FuzzyStartTime():
    return (
        FuzzyNaiveDateTime(
        datetime.datetime.now() - datetime.timedelta(days=40),
        datetime.datetime.now() - datetime.timedelta(days=20),
        )
    )


def FuzzyEndTime():
    return (
        FuzzyNaiveDateTime(
            datetime.datetime.now() - datetime.timedelta(days=19),
            datetime.datetime.now()
        )
    )


all_unicode = ''.join(chr(i) for i in range(65536))
UNICODE_LETTERS = ''.join(c for c in all_unicode if unicodedata.category(c) == 'Lu' or unicodedata.category(c) == 'Ll')


class FaradayFactory(factory.alchemy.SQLAlchemyModelFactory):

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

    name = FuzzyText(chars=string.ascii_lowercase + string.digits)
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Workspace
        sqlalchemy_session = db.session


class WorkspaceObjectFactory(FaradayFactory):
    workspace = factory.SubFactory(WorkspaceFactory)
    creator = factory.SubFactory(UserFactory)

    @classmethod
    def build_dict(cls, **kwargs):
        ret = super().build_dict(**kwargs)
        del ret['workspace']  # It is passed in the URL, not in POST data
        return ret


class FuzzyIncrementalInteger(BaseFuzzyAttribute):
    """Like a FuzzyInteger, but tries to prevent generating duplicated
    values"""

    def __init__(self, low, high, **kwargs):
        self.iterator = itertools.cycle(range(low, high - 1))
        super().__init__(**kwargs)

    def fuzz(self):
        return next(self.iterator)


class HostFactory(WorkspaceObjectFactory):
    id = FuzzyIncrementalInteger(1, 65535)
    ip = FuzzyText()
    description = FuzzyText()
    os = FuzzyChoice(['Linux', 'Windows', 'OSX', 'Android', 'iOS'])
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Host
        sqlalchemy_session = db.session


class HostnameFactory(WorkspaceObjectFactory):
    name = FuzzyText()
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
    port = FuzzyIncrementalInteger(1, 65535)
    protocol = FuzzyChoice(['TCP', 'UDP'])
    host = factory.SubFactory(HostFactory, workspace=factory.SelfAttribute('..workspace'))
    status = FuzzyChoice(Service.STATUSES)
    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = Service
        sqlalchemy_session = db.session

    @classmethod
    def build_dict(cls, **kwargs):
        ret = super().build_dict(**kwargs)
        ret['host'].workspace = kwargs['workspace']
        ret['parent'] = ret['host'].id
        ret['ports'] = [ret['port']]
        ret.pop('host')
        return ret


class SourceCodeFactory(WorkspaceObjectFactory):
    filename = FuzzyText()

    class Meta:
        model = SourceCode
        sqlalchemy_session = db.session


class CustomFieldsSchemaFactory(FaradayFactory):

    field_name = FuzzyText()
    field_type = FuzzyText()
    field_display_name = FuzzyText()
    field_order = FuzzyInteger(1, 10)
    table_name = FuzzyText()

    class Meta:
        model = CustomFieldsSchema
        sqlalchemy_session = db.session


class VulnerabilityGenericFactory(WorkspaceObjectFactory):
    name = FuzzyText()
    description = FuzzyText()
    creator = factory.SubFactory(UserFactory)
    severity = FuzzyChoice(['critical', 'high'])


class HasParentHostOrService(WorkspaceObjectFactory):
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
        return super().attributes(create, extra)

    @classmethod
    def _after_postgeneration(cls, obj, create, results=None):
        super()._after_postgeneration(obj, create, results)
        if isinstance(obj, dict):
            # This happens when built with build_dict
            if obj['host'] and obj['service']:
                if random.choice([True, False]):
                    obj['host'] = None
                else:
                    obj['service'] = None
        elif obj.host and obj.service:
            # Setting both service and host to a vuln is not allowed.
            # This will pick one of them randomly.
            # TODO: Check is this is recommended
            if random.choice([True, False]):
                obj.host = None
            else:
                obj.service = None
            session = cls._meta.sqlalchemy_session
            session.add(obj)
            session.commit()

    @classmethod
    def build_dict(cls, **kwargs):
        ret = super().build_dict(**kwargs)
        service = ret.pop('service')
        host = ret.pop('host')
        if host is not None:
            assert service is None

            # This should be set by the SelfAttribute of the SubFactory, but I
            # don't kwown why it doesn't work here
            host.workspace = kwargs.get('workspace', host.workspace)

            db.session.add(host)
            db.session.commit()  # Needed to get the object IDs
            ret['parent_type'] = 'Host'
            ret['parent'] = host.id
        elif service is not None:
            assert host is None

            # This should be set by the SelfAttribute of the SubFactory, but I
            # don't kwown why it doesn't work here
            service.workspace = service.host.workspace = kwargs.get(
                'workspace', service.workspace)

            db.session.add(service)
            db.session.commit()  # Needed to get the object IDs
            ret['parent_type'] = 'Service'
            ret['parent'] = service.id
        else:
            raise ValueError("Either host or service must be set")
        return ret


class VulnerabilityFactory(VulnerabilityGenericFactory,
                           HasParentHostOrService):

    host = factory.SubFactory(HostFactory, workspace=factory.SelfAttribute('..workspace'))
    service = factory.SubFactory(ServiceFactory, workspace=factory.SelfAttribute('..workspace'))
    description = FuzzyText()
    type = "vulnerability"

    @classmethod
    def build_dict(cls, **kwargs):
        ret = super().build_dict(**kwargs)
        assert ret['type'] == 'vulnerability'
        ret['type'] = 'Vulnerability'
        return ret

    class Meta:
        model = Vulnerability
        sqlalchemy_session = db.session


class VulnerabilityWebFactory(VulnerabilityGenericFactory):
    method = FuzzyChoice(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
    parameter_name = FuzzyText()
    service = factory.SubFactory(ServiceFactory, workspace=factory.SelfAttribute('..workspace'))
    type = "vulnerability_web"

    @classmethod
    def build_dict(cls, **kwargs):
        ret = super().build_dict(**kwargs)
        assert ret['type'] == 'vulnerability_web'
        ret['type'] = 'VulnerabilityWeb'
        return ret

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

    @classmethod
    def build_dict(cls, **kwargs):
        ret = super().build_dict(**kwargs)
        ret['exploitation'] = ret['severity']
        return ret


class CredentialFactory(HasParentHostOrService, WorkspaceObjectFactory):
    host = factory.SubFactory(
        HostFactory, workspace=factory.SelfAttribute('..workspace')
    )
    service = factory.SubFactory(
        ServiceFactory, workspace=factory.SelfAttribute('..workspace')
    )
    username = FuzzyText()
    password = FuzzyText()

    class Meta:
        model = Credential
        sqlalchemy_session = db.session


class CommandObjectFactory(FaradayFactory):
    workspace = factory.SubFactory(WorkspaceFactory)
    created_persistent = False

    class Meta:
        model = CommandObject
        sqlalchemy_session = db.session


class CommandFactory(WorkspaceObjectFactory):
    command = FuzzyText()
    tool = FuzzyText()
    end_date = FuzzyDateTime(datetime.datetime.utcnow().replace(tzinfo=pytz.utc) + datetime.timedelta(20), datetime.datetime.utcnow().replace(tzinfo=pytz.utc) + datetime.timedelta(30))
    start_date = FuzzyDateTime(datetime.datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.timedelta(30), datetime.datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.timedelta(20))
    ip = FuzzyText()
    user = FuzzyText()
    hostname = FuzzyText()
    import_source = 'shell'

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
                object_type='vulnerability',
                object_id=vuln.id,
                command=self,
                workspace=self.workspace
            )
            CommandObjectFactory.create(
                object_type='host',
                object_id=host.id,
                command=self,
                workspace=self.workspace
            )

    @classmethod
    def build_dict(cls, **kwargs):
        # Ugly hack to JSON-serialize datetimes
        ret = super().build_dict(**kwargs)
        ret['itime'] = time.mktime(ret['start_date'].utctimetuple())
        ret['duration'] = (ret['end_date'] - ret['start_date']).seconds + ((ret['end_date'] - ret['start_date']).microseconds / 1000000.0)
        ret.pop('start_date')
        ret.pop('end_date')
        return ret


class EmptyCommandFactory(WorkspaceObjectFactory):
    """
        A command without command objects.
    """
    command = FuzzyText()
    tool = FuzzyText()
    end_date = FuzzyDateTime(datetime.datetime.utcnow().replace(tzinfo=pytz.utc) + datetime.timedelta(20), datetime.datetime.utcnow().replace(tzinfo=pytz.utc) + datetime.timedelta(30))
    start_date = FuzzyDateTime(datetime.datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.timedelta(30), datetime.datetime.utcnow().replace(tzinfo=pytz.utc) - datetime.timedelta(20))
    ip = FuzzyText()
    user = FuzzyText()
    hostname = FuzzyText()
    import_source = 'shell'

    class Meta:
        model = Command
        sqlalchemy_session = db.session


class CommentFactory(WorkspaceObjectFactory):
    """
        A command without command objects.
    """
    text = FuzzyText()
    object_id = FuzzyInteger(1, 10000)
    object_type = FuzzyChoice(['host', 'service', 'comment', 'vulnerability'])

    @classmethod
    def build_dict(cls, **kwargs):
        # The host, service or comment must be created
        ret = super().build_dict(**kwargs)
        workspace = kwargs['workspace']
        if ret['object_type'] == 'host':
            HostFactory.create(workspace=workspace, id=ret['object_id'])
        elif ret['object_type'] == 'service':
            ServiceFactory.create(workspace=workspace, id=ret['object_id'])
        elif ret['object_type'] == 'vulnerability':
            VulnerabilityFactory.create(workspace=workspace, id=ret['object_id'])
        elif ret['object_type'] == 'comment':
            cls.create(workspace=workspace, id=ret['object_id'])
        return ret

    class Meta:
        model = Comment
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
        ret = super().build_dict(**kwargs)
        ret['start'] = ret['start_date'].isoformat()
        ret['end'] = ret['end_date'].isoformat()
        ret.pop('start_date')
        ret.pop('end_date')
        return ret


class TagFactory(FaradayFactory):
    name = FuzzyText()
    slug = FuzzyText()

    class Meta:
        model = Tag
        sqlalchemy_session = db.session


class NoteFactory(FaradayFactory):

    class Meta:
        model = Comment


class AgentFactory(FaradayFactory):
    name = FuzzyText()
    active = True
    id = FuzzyIncrementalInteger(1, 10000)

    @factory.post_generation
    def workspaces(self, create, extracted, **kwargs):
        if not create:
            # Simple build, do nothing.
            if extracted:
                # A list of groups were passed in, use them
                self['workspaces'] = []
                for workspace in extracted:
                    self['workspaces'].append(workspace.name)
            else:
                self['workspaces'] = [WorkspaceFactory().name, WorkspaceFactory().name]

        elif extracted:
            # A list of groups were passed in, use them
            for workspace in extracted:
                self.workspaces.append(workspace)
        else:
            self.workspaces.append(WorkspaceFactory())
            self.workspaces.append(WorkspaceFactory())

    @classmethod
    def build_dict(cls, **kwargs):
        return super().build_dict(**kwargs)

    class Meta:
        model = Agent
        sqlalchemy_session = db.session


class ExecutorFactory(FaradayFactory):
    name = FuzzyText()
    agent = factory.SubFactory(AgentFactory)
    parameters_metadata = factory.LazyAttribute(
        lambda e: {"param_name": False}
    )

    class Meta:
        model = Executor
        sqlalchemy_session = db.session


class AgentExecutionFactory(WorkspaceObjectFactory):
    executor = factory.SubFactory(
        ExecutorFactory,
    )
    parameters_data = factory.LazyAttribute(
        lambda _: {"param_name": "param_value"}
    )
    workspace = factory.LazyAttribute(
        lambda agent_execution: agent_execution.executor.agent.workspaces[0]
    )
    command = factory.SubFactory(
        EmptyCommandFactory,
        workspace=factory.SelfAttribute("..workspace"),
        end_date=None
    )

    class Meta:
        model = AgentExecution
        sqlalchemy_session = db.session


class SearchFilterFactory(FaradayFactory):

    name = FuzzyText()
    user_query = FuzzyText()
    json_query = FuzzyText()

    creator = factory.SubFactory(UserFactory)

    class Meta:
        model = SearchFilter
        sqlalchemy_session = db.session


class ActionFactory(FaradayFactory):
    name = FuzzyText()
    command = FuzzyChoice(['UPDATE', 'DELETE', 'ALERT'])
    field = 'severity'
    value = 'informational'

    class Meta:
        model = Action
        sqlalchemy_session = db.session


class ConditionFactory(FaradayFactory):
    field = 'description'
    value = FuzzyText()
    operator = 'equals'

    class Meta:
        model = Condition
        sqlalchemy_session = db.session


class RuleFactory(WorkspaceObjectFactory):
    model = 'Vulnerability'
    disabled = FuzzyChoice([True, False])
    workspace = factory.SubFactory(WorkspaceFactory)

    class Meta:
        model = Rule
        # sqlalchemy_session = db.session


class RuleActionFactory(FaradayFactory):
    rule = factory.SubFactory(RuleFactory)
    action = factory.SubFactory(ActionFactory)

    class Meta:
        model = RuleAction
        sqlalchemy_session = db.session

# I'm Py3
