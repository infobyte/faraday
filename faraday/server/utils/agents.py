from datetime import datetime
import logging
from typing import Tuple

from faraday.server.models import Command, AgentExecution, Executor, Workspace

logger = logging.getLogger(__name__)


def get_command_and_agent_execution(
        executor: Executor,
        parameters: dict,
        workspace: Workspace,
        username: str = '',
        hostname: str = '',
        message: str = ''
) -> Tuple[Command, AgentExecution]:
    params = ', '.join([f'{key}={value}' for (key, value) in parameters.items()])

    command = Command(
        import_source="agent",
        tool=executor.agent.name,
        command=executor.name,
        user=username,
        hostname=hostname,
        params=params,
        start_date=datetime.utcnow(),
        workspace=workspace
    )

    agent_execution = AgentExecution(
        running=None,
        successful=None,
        message=message,
        executor=executor,
        workspace_id=workspace.id,
        parameters_data=parameters,
        command=command
    )
    return command, agent_execution
