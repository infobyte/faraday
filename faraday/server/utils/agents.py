"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging
from datetime import datetime
from typing import Tuple
from uuid import UUID

# Local application imports
from sqlalchemy import func

from faraday.server.models import Agent, AgentManifest, Command, AgentExecution, Executor, Workspace, db

logger = logging.getLogger(__name__)


def get_bundled_manifests() -> dict:
    """Manifests announced by the agents, for the digests that were received completely."""
    announced = db.session.query(Agent.manifests_digest, Agent.manifests_count).filter(
        Agent.manifests_digest.isnot(None), Agent.manifests_count > 0
    ).distinct().subquery()
    stored = db.session.query(AgentManifest.manifests_digest, func.count().label('stored')).group_by(
        AgentManifest.manifests_digest
    ).subquery()
    complete = db.session.query(announced.c.manifests_digest).join(
        stored, stored.c.manifests_digest == announced.c.manifests_digest
    ).filter(stored.c.stored >= announced.c.manifests_count)
    rows = AgentManifest.query.filter(AgentManifest.manifests_digest.in_(complete)).order_by(
        AgentManifest.manifests_digest, AgentManifest.name
    )
    manifests = {}
    for row in rows:
        manifests.setdefault(row.name, row.manifest)
    return manifests


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
