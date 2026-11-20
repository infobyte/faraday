"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging
from datetime import datetime
from typing import Optional, Tuple
from uuid import UUID

# Local application imports
from sqlalchemy import update

from faraday.server.models import Agent, Command, AgentExecution, Executor, Workspace, db, generate_agent_token

logger = logging.getLogger(__name__)


def claim_pending_agent(dispatcher_id: str) -> Optional[Agent]:
    """Claims the agent that waits for the dispatcher with that id.

    It is one conditional UPDATE, so two dispatchers with the same id cannot claim the same agent. The agent gets a
    new token, so the one it had when it was created in advance stops working.
    """
    claimed_id = db.session.execute(
        update(Agent).where(Agent.dispatcher_id == dispatcher_id).values(
            dispatcher_id=None, token=generate_agent_token()
        ).returning(Agent.id)
    ).scalar()
    db.session.commit()
    return db.session.get(Agent, claimed_id) if claimed_id is not None else None


def get_command_and_agent_execution(
        executor: Executor,
        parameters: dict,
        workspace: Workspace,
        user_id: int,
        run_uuid: UUID,
        username: str = '',
        hostname: str = '',
        message: str = '',
        triggered_by: str = '',
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
        workspace=workspace,
        creator_id=user_id
    )

    agent_execution = AgentExecution(
        running=None,
        successful=None,
        message=message,
        executor=executor,
        workspace_id=workspace.id,
        parameters_data=parameters,
        command=command,
        triggered_by=triggered_by,
        run_uuid=run_uuid
    )
    return command, agent_execution
