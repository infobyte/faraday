from tests.test_api_non_workspaced_base import ReadOnlyAPITests
from faraday.server.models import AgentExecution
from tests import factories
from faraday.server.api.modules.agent_execution import AgentExecutionView


class TestAgentExecution(ReadOnlyAPITests):

    model = AgentExecution
    factory = factories.AgentExecutionFactory
    view_class = AgentExecutionView
    api_endpoint = 'agent_executions'
